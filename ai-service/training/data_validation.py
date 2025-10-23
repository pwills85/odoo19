"""
Data Validation for Training Dataset
====================================

Validates extracted data quality before training.
"""

import pandas as pd
import json
import logging
from typing import Dict, List, Tuple
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataValidator:
    """Validates training data quality."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize validator with DataFrame.

        Args:
            df: DataFrame from data_extraction.py
        """
        self.df = df
        self.validation_results = {}
        self.errors = []
        self.warnings = []

    def validate_all(self) -> Tuple[bool, Dict]:
        """
        Run all validation checks.

        Returns:
            Tuple of (is_valid, validation_report)
        """
        logger.info("🔍 Starting data validation...")

        # Run all checks
        self._check_required_columns()
        self._check_nulls()
        self._check_data_types()
        self._check_date_range()
        self._check_duplicates()
        self._check_analytic_distribution()
        self._check_account_consistency()
        self._check_supplier_quality()
        self._check_product_quality()
        self._check_statistical_outliers()

        # Generate report
        is_valid = len(self.errors) == 0
        report = self._generate_report()

        return is_valid, report

    def _check_required_columns(self):
        """Check all required columns exist."""
        required = [
            'line_id', 'invoice_id', 'invoice_date',
            'supplier_id', 'supplier_name',
            'account_id', 'account_code', 'account_name',
            'price_subtotal'
        ]

        missing = [col for col in required if col not in self.df.columns]

        if missing:
            self.errors.append(f"Missing required columns: {missing}")
        else:
            logger.info("✅ All required columns present")

    def _check_nulls(self):
        """Check for unexpected null values."""
        # Critical columns that should never be null
        critical_nulls = {
            'invoice_id': self.df['invoice_id'].isna().sum(),
            'invoice_date': self.df['invoice_date'].isna().sum(),
            'supplier_id': self.df['supplier_id'].isna().sum(),
            'account_id': self.df['account_id'].isna().sum(),
        }

        for col, null_count in critical_nulls.items():
            if null_count > 0:
                self.errors.append(f"{col} has {null_count} null values (should be 0)")

        # Acceptable nulls (warnings only)
        acceptable_nulls = {
            'product_id': self.df['product_id'].isna().sum(),
            'product_code': self.df['product_code'].isna().sum(),
            'analytic_distribution': self.df['analytic_distribution'].isna().sum(),
            'purchase_order_id': self.df['purchase_order_id'].isna().sum(),
        }

        for col, null_count in acceptable_nulls.items():
            if null_count > 0:
                pct = (null_count / len(self.df)) * 100
                if pct > 50:
                    self.warnings.append(f"{col}: {null_count} nulls ({pct:.1f}%) - High null rate")
                else:
                    logger.info(f"ℹ️  {col}: {null_count} nulls ({pct:.1f}%)")

    def _check_data_types(self):
        """Validate data types."""
        # Numeric columns
        numeric_cols = ['line_id', 'invoice_id', 'supplier_id', 'product_id',
                       'quantity', 'price_unit', 'price_subtotal']

        for col in numeric_cols:
            if col in self.df.columns:
                if not pd.api.types.is_numeric_dtype(self.df[col]):
                    self.errors.append(f"{col} should be numeric")

        # Date columns
        if 'invoice_date' in self.df.columns:
            if not pd.api.types.is_datetime64_any_dtype(self.df['invoice_date']):
                try:
                    self.df['invoice_date'] = pd.to_datetime(self.df['invoice_date'])
                    logger.info("✅ Converted invoice_date to datetime")
                except:
                    self.errors.append("invoice_date cannot be converted to datetime")

    def _check_date_range(self):
        """Validate date range is reasonable."""
        if 'invoice_date' not in self.df.columns:
            return

        min_date = self.df['invoice_date'].min()
        max_date = self.df['invoice_date'].max()
        date_range_days = (max_date - min_date).days

        logger.info(f"📅 Date range: {min_date} to {max_date} ({date_range_days} days)")

        # Check for future dates
        if max_date > pd.Timestamp.now():
            self.warnings.append(f"Future invoice dates found (max: {max_date})")

        # Check for very old dates (>20 years)
        if date_range_days > 20 * 365:
            self.warnings.append(f"Very wide date range: {date_range_days} days")

    def _check_duplicates(self):
        """Check for duplicate lines."""
        duplicates = self.df.duplicated(subset=['line_id']).sum()

        if duplicates > 0:
            self.errors.append(f"Found {duplicates} duplicate line_id values")
        else:
            logger.info("✅ No duplicate line_ids")

    def _check_analytic_distribution(self):
        """Validate analytic_distribution JSON structure."""
        if 'analytic_distribution' not in self.df.columns:
            return

        analytics_with_data = self.df['analytic_distribution'].notna()
        total_with_analytics = analytics_with_data.sum()

        if total_with_analytics == 0:
            self.warnings.append("⚠️  No invoice lines have analytic_distribution - AI training will have no ground truth!")
            return

        logger.info(f"📊 Lines with analytics: {total_with_analytics} / {len(self.df)} ({total_with_analytics/len(self.df)*100:.1f}%)")

        # Validate JSON structure
        invalid_json = 0
        for idx, value in self.df[analytics_with_data]['analytic_distribution'].items():
            try:
                if isinstance(value, str):
                    parsed = json.loads(value)
                    if not isinstance(parsed, dict):
                        invalid_json += 1
            except (json.JSONDecodeError, TypeError):
                invalid_json += 1

        if invalid_json > 0:
            self.warnings.append(f"{invalid_json} lines have invalid analytic_distribution JSON")

    def _check_account_consistency(self):
        """Check account mapping consistency."""
        if 'account_id' not in self.df.columns:
            return

        # Check if account_code and account_name match account_id
        account_mapping = self.df.groupby('account_id').agg({
            'account_code': 'nunique',
            'account_name': 'nunique'
        })

        inconsistent = account_mapping[(account_mapping['account_code'] > 1) |
                                       (account_mapping['account_name'] > 1)]

        if len(inconsistent) > 0:
            self.warnings.append(f"{len(inconsistent)} accounts have inconsistent code/name mappings")

        # Log account distribution
        top_accounts = self.df['account_code'].value_counts().head(10)
        logger.info(f"📊 Top 10 accounts: {dict(top_accounts)}")

    def _check_supplier_quality(self):
        """Check supplier data quality."""
        if 'supplier_id' not in self.df.columns:
            return

        # Check RUT presence (important for Chile)
        suppliers_without_rut = self.df['supplier_rut'].isna().sum()
        if suppliers_without_rut > 0:
            pct = (suppliers_without_rut / len(self.df)) * 100
            if pct > 10:
                self.warnings.append(f"{suppliers_without_rut} lines ({pct:.1f}%) have suppliers without RUT")

        # Check supplier name consistency
        supplier_names = self.df.groupby('supplier_id')['supplier_name'].nunique()
        inconsistent_names = supplier_names[supplier_names > 1]

        if len(inconsistent_names) > 0:
            self.warnings.append(f"{len(inconsistent_names)} suppliers have multiple names")

        # Log supplier distribution
        unique_suppliers = self.df['supplier_id'].nunique()
        logger.info(f"📊 Unique suppliers: {unique_suppliers}")

    def _check_product_quality(self):
        """Check product data quality."""
        if 'product_id' not in self.df.columns:
            return

        # Lines without product (text-only lines are OK)
        lines_without_product = self.df['product_id'].isna().sum()
        pct = (lines_without_product / len(self.df)) * 100

        if pct > 30:
            self.warnings.append(f"{lines_without_product} lines ({pct:.1f}%) have no product - High percentage")
        else:
            logger.info(f"ℹ️  {lines_without_product} lines ({pct:.1f}%) have no product (acceptable)")

        # Products with codes
        products_with_code = self.df['product_code'].notna().sum()
        total_products = self.df['product_id'].notna().sum()

        if total_products > 0:
            pct_with_code = (products_with_code / total_products) * 100
            logger.info(f"📊 Products with code: {products_with_code} / {total_products} ({pct_with_code:.1f}%)")

    def _check_statistical_outliers(self):
        """Detect statistical outliers."""
        # Check for zero or negative amounts
        if 'price_subtotal' in self.df.columns:
            zero_amounts = (self.df['price_subtotal'] == 0).sum()
            negative_amounts = (self.df['price_subtotal'] < 0).sum()

            if zero_amounts > 0:
                pct = (zero_amounts / len(self.df)) * 100
                if pct > 5:
                    self.warnings.append(f"{zero_amounts} lines ({pct:.1f}%) have zero amount")

            if negative_amounts > 0:
                pct = (negative_amounts / len(self.df)) * 100
                logger.info(f"ℹ️  {negative_amounts} lines ({pct:.1f}%) have negative amount (credit notes/refunds)")

        # Check for extreme quantities
        if 'quantity' in self.df.columns:
            extreme_qty = (self.df['quantity'].abs() > 10000).sum()
            if extreme_qty > 0:
                self.warnings.append(f"{extreme_qty} lines have quantity > 10,000 (possible data error)")

    def _generate_report(self) -> Dict:
        """Generate validation report."""
        report = {
            'validation_timestamp': pd.Timestamp.now().isoformat(),
            'total_records': len(self.df),
            'is_valid': len(self.errors) == 0,
            'errors': self.errors,
            'warnings': self.warnings,
            'data_quality_scores': {
                'completeness': self._calculate_completeness_score(),
                'consistency': self._calculate_consistency_score(),
                'accuracy': self._calculate_accuracy_score(),
            },
            'recommendations': self._generate_recommendations()
        }

        return report

    def _calculate_completeness_score(self) -> float:
        """Calculate data completeness score (0-100)."""
        # Weight critical columns more
        weights = {
            'invoice_id': 3,
            'invoice_date': 3,
            'supplier_id': 3,
            'account_id': 3,
            'analytic_distribution': 2,
            'product_id': 1,
            'purchase_order_id': 1,
        }

        total_weight = 0
        weighted_completeness = 0

        for col, weight in weights.items():
            if col in self.df.columns:
                completeness = 1 - (self.df[col].isna().sum() / len(self.df))
                weighted_completeness += completeness * weight
                total_weight += weight

        return (weighted_completeness / total_weight) * 100 if total_weight > 0 else 0

    def _calculate_consistency_score(self) -> float:
        """Calculate data consistency score (0-100)."""
        # Start with 100 and deduct points for inconsistencies
        score = 100.0

        # Deduct for duplicate IDs
        duplicates = self.df.duplicated(subset=['line_id']).sum()
        if duplicates > 0:
            score -= min(20, duplicates / len(self.df) * 100)

        # Deduct for inconsistent mappings
        if 'account_id' in self.df.columns:
            account_mapping = self.df.groupby('account_id')['account_code'].nunique()
            inconsistent = (account_mapping > 1).sum()
            if inconsistent > 0:
                score -= min(15, inconsistent)

        return max(0, score)

    def _calculate_accuracy_score(self) -> float:
        """Calculate data accuracy score (0-100)."""
        score = 100.0

        # Deduct for future dates
        if 'invoice_date' in self.df.columns:
            future_dates = (self.df['invoice_date'] > pd.Timestamp.now()).sum()
            if future_dates > 0:
                score -= min(10, future_dates / len(self.df) * 100)

        # Deduct for negative quantities (should be rare)
        if 'quantity' in self.df.columns:
            negative_qty = (self.df['quantity'] < 0).sum()
            if negative_qty > len(self.df) * 0.05:  # More than 5%
                score -= 10

        return max(0, score)

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on validation."""
        recommendations = []

        # Check analytics coverage
        if 'analytic_distribution' in self.df.columns:
            analytics_pct = (self.df['analytic_distribution'].notna().sum() / len(self.df)) * 100
            if analytics_pct < 50:
                recommendations.append(
                    f"⚠️  Only {analytics_pct:.1f}% of lines have analytic_distribution. "
                    "AI model accuracy will be limited. Consider manual data enrichment."
                )
            elif analytics_pct >= 80:
                recommendations.append(
                    f"✅ Excellent analytics coverage ({analytics_pct:.1f}%). "
                    "Expect high AI model accuracy (>90%)."
                )

        # Check PO linking
        if 'purchase_order_id' in self.df.columns:
            po_pct = (self.df['purchase_order_id'].notna().sum() / len(self.df)) * 100
            if po_pct > 70:
                recommendations.append(
                    f"✅ High PO linking ({po_pct:.1f}%). "
                    "Good for extracting analytic accounts from POs."
                )

        # Check data volume
        if len(self.df) < 10000:
            recommendations.append(
                f"⚠️  Small dataset ({len(self.df)} lines). "
                "Consider extracting more years for better model training."
            )
        elif len(self.df) > 100000:
            recommendations.append(
                f"✅ Large dataset ({len(self.df)} lines). "
                "Excellent for training robust AI models."
            )

        return recommendations

    def print_report(self, report: Dict):
        """Print formatted validation report."""
        print("\n" + "=" * 80)
        print("DATA VALIDATION REPORT")
        print("=" * 80)
        print(f"\n📊 Total Records: {report['total_records']:,}")
        print(f"✅ Valid: {report['is_valid']}")

        print("\n📈 Data Quality Scores:")
        scores = report['data_quality_scores']
        print(f"   - Completeness: {scores['completeness']:.1f}/100")
        print(f"   - Consistency:  {scores['consistency']:.1f}/100")
        print(f"   - Accuracy:     {scores['accuracy']:.1f}/100")

        if report['errors']:
            print("\n❌ Errors:")
            for error in report['errors']:
                print(f"   - {error}")

        if report['warnings']:
            print("\n⚠️  Warnings:")
            for warning in report['warnings']:
                print(f"   - {warning}")

        if report['recommendations']:
            print("\n💡 Recommendations:")
            for rec in report['recommendations']:
                print(f"   {rec}")

        print("\n" + "=" * 80)


def main():
    """Main execution."""
    print("=" * 80)
    print("DATA VALIDATION")
    print("=" * 80)
    print()

    # Load data
    data_file = "/app/training/data/historical_invoice_lines_7years.csv"
    print(f"📂 Loading: {data_file}")

    try:
        df = pd.read_csv(data_file)
        print(f"✅ Loaded {len(df):,} records")
    except FileNotFoundError:
        print(f"❌ File not found: {data_file}")
        print("   Run data_extraction.py first!")
        return

    # Validate
    validator = DataValidator(df)
    is_valid, report = validator.validate_all()

    # Print report
    validator.print_report(report)

    # Save report
    report_file = "/app/training/data/validation_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n💾 Report saved to: {report_file}")

    # Exit with appropriate code
    if not is_valid:
        print("\n❌ Validation FAILED - Fix errors before proceeding to training")
        exit(1)
    else:
        print("\n✅ Validation PASSED - Proceed to data_cleaning.py")
        exit(0)


if __name__ == '__main__':
    main()
