"""
Data Cleaning for Training Dataset
==================================

Cleans and prepares data for ML training and embeddings creation.
"""

import pandas as pd
import numpy as np
import json
import re
import logging
from typing import Dict, List, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataCleaner:
    """Cleans training data for ML and embeddings."""

    def __init__(self, df: pd.DataFrame):
        """
        Initialize cleaner with DataFrame.

        Args:
            df: DataFrame from data_extraction.py
        """
        self.df = df.copy()  # Work on copy
        self.original_count = len(df)
        self.cleaning_log = []

    def clean_all(self) -> pd.DataFrame:
        """
        Run all cleaning steps.

        Returns:
            Cleaned DataFrame
        """
        logger.info("🧹 Starting data cleaning...")
        logger.info(f"   Original records: {self.original_count:,}")

        # Run cleaning steps
        self._remove_duplicates()
        self._handle_nulls()
        self._clean_text_fields()
        self._normalize_amounts()
        self._parse_analytic_distribution()
        self._extract_analytic_accounts()
        self._create_composite_features()
        self._filter_invalid_records()

        # Log results
        final_count = len(self.df)
        removed = self.original_count - final_count
        logger.info(f"✅ Cleaning complete:")
        logger.info(f"   - Final records: {final_count:,}")
        logger.info(f"   - Removed: {removed:,} ({removed/self.original_count*100:.2f}%)")

        return self.df

    def _remove_duplicates(self):
        """Remove duplicate records."""
        before = len(self.df)
        self.df = self.df.drop_duplicates(subset=['line_id'])
        after = len(self.df)

        removed = before - after
        if removed > 0:
            logger.info(f"🗑️  Removed {removed} duplicate records")
            self.cleaning_log.append(f"Removed {removed} duplicates")

    def _handle_nulls(self):
        """Handle null values intelligently."""
        # Fill empty product names with description
        if 'product_name' in self.df.columns and 'description' in self.df.columns:
            null_products = self.df['product_name'].isna()
            self.df.loc[null_products, 'product_name'] = self.df.loc[null_products, 'description']
            logger.info(f"📝 Filled {null_products.sum()} null product_name with description")

        # Fill null product codes with 'NO_CODE'
        if 'product_code' in self.df.columns:
            self.df['product_code'] = self.df['product_code'].fillna('NO_CODE')

        # Fill null categories with 'UNCATEGORIZED'
        if 'product_category' in self.df.columns:
            self.df['product_category'] = self.df['product_category'].fillna('UNCATEGORIZED')

        # Fill null RUT with 'SIN_RUT'
        if 'supplier_rut' in self.df.columns:
            self.df['supplier_rut'] = self.df['supplier_rut'].fillna('SIN_RUT')

    def _clean_text_fields(self):
        """Clean and normalize text fields."""
        text_fields = ['supplier_name', 'product_name', 'description', 'account_name']

        for field in text_fields:
            if field not in self.df.columns:
                continue

            # Remove extra whitespace
            self.df[field] = self.df[field].str.strip()
            self.df[field] = self.df[field].str.replace(r'\s+', ' ', regex=True)

            # Remove special characters (keep alphanumeric, spaces, and basic punctuation)
            self.df[field] = self.df[field].str.replace(r'[^\w\s\-\.\,]', '', regex=True)

            # Convert to uppercase for consistency
            self.df[field] = self.df[field].str.upper()

        logger.info("✨ Cleaned text fields")

    def _normalize_amounts(self):
        """Normalize monetary amounts."""
        if 'price_subtotal' in self.df.columns:
            # Convert to absolute values (handle credit notes separately)
            self.df['amount_abs'] = self.df['price_subtotal'].abs()

            # Flag credit notes/refunds
            self.df['is_credit_note'] = self.df['price_subtotal'] < 0

            # Calculate log amount (for ML features)
            self.df['log_amount'] = np.log1p(self.df['amount_abs'])

            logger.info("💰 Normalized amounts")

    def _parse_analytic_distribution(self):
        """Parse analytic_distribution JSON into structured format."""
        if 'analytic_distribution' not in self.df.columns:
            return

        def parse_json(value):
            """Parse analytic JSON safely."""
            if pd.isna(value):
                return None
            try:
                if isinstance(value, str):
                    return json.loads(value)
                elif isinstance(value, dict):
                    return value
                else:
                    return None
            except (json.JSONDecodeError, TypeError):
                return None

        # Parse JSON
        self.df['analytic_parsed'] = self.df['analytic_distribution'].apply(parse_json)

        # Count analytics parsed
        parsed_count = self.df['analytic_parsed'].notna().sum()
        logger.info(f"📊 Parsed {parsed_count:,} analytic distributions")

    def _extract_analytic_accounts(self):
        """Extract analytic account IDs from parsed distribution."""
        if 'analytic_parsed' not in self.df.columns:
            return

        def extract_accounts(parsed_dict):
            """Extract account IDs from analytic distribution."""
            if not parsed_dict:
                return []
            # In Odoo, analytic_distribution is like: {"123": 100.0, "456": 50.0}
            # where keys are analytic account IDs
            return list(parsed_dict.keys())

        self.df['analytic_account_ids'] = self.df['analytic_parsed'].apply(extract_accounts)

        # Extract primary analytic account (highest percentage)
        def get_primary_account(parsed_dict):
            """Get analytic account with highest percentage."""
            if not parsed_dict:
                return None
            return max(parsed_dict.items(), key=lambda x: x[1])[0]

        self.df['primary_analytic_account_id'] = self.df['analytic_parsed'].apply(get_primary_account)

        # Count lines with analytics
        with_analytics = (self.df['analytic_account_ids'].str.len() > 0).sum()
        logger.info(f"📌 Extracted {with_analytics:,} lines with analytic accounts")

    def _create_composite_features(self):
        """Create composite features for ML training."""
        # Supplier + Product combination (key for matching)
        if 'supplier_id' in self.df.columns and 'product_id' in self.df.columns:
            self.df['supplier_product_key'] = (
                self.df['supplier_id'].astype(str) + '_' +
                self.df['product_id'].fillna(0).astype(int).astype(str)
            )

        # Text for embeddings (combine multiple fields)
        text_parts = []

        if 'supplier_name' in self.df.columns:
            text_parts.append(self.df['supplier_name'].fillna(''))

        if 'product_name' in self.df.columns:
            text_parts.append(self.df['product_name'].fillna(''))

        if 'product_code' in self.df.columns:
            text_parts.append(self.df['product_code'].fillna(''))

        if 'product_category' in self.df.columns:
            text_parts.append(self.df['product_category'].fillna(''))

        if 'description' in self.df.columns:
            text_parts.append(self.df['description'].fillna(''))

        # Combine all text
        self.df['full_text'] = ' | '.join([part.astype(str) for part in text_parts])

        # Clean combined text
        self.df['full_text'] = self.df['full_text'].str.strip()
        self.df['full_text'] = self.df['full_text'].str.replace(r'\s+', ' ', regex=True)

        logger.info("🔗 Created composite features")

    def _filter_invalid_records(self):
        """Remove invalid records that cannot be used for training."""
        before = len(self.df)

        # Remove records without account (this is our ground truth!)
        if 'account_id' in self.df.columns:
            self.df = self.df[self.df['account_id'].notna()]

        # Remove records with zero text (cannot create embeddings)
        if 'full_text' in self.df.columns:
            self.df = self.df[self.df['full_text'].str.len() > 10]

        after = len(self.df)
        removed = before - after

        if removed > 0:
            logger.info(f"🗑️  Filtered {removed} invalid records")
            self.cleaning_log.append(f"Filtered {removed} invalid records")

    def split_train_test(
        self,
        test_size: float = 0.2,
        random_state: int = 42,
        stratify_by: Optional[str] = 'account_id'
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Split data into train and test sets.

        Args:
            test_size: Proportion of test set (0.2 = 20%)
            random_state: Random seed for reproducibility
            stratify_by: Column to stratify split (ensures balanced distribution)

        Returns:
            Tuple of (train_df, test_df)
        """
        from sklearn.model_selection import train_test_split

        stratify = self.df[stratify_by] if stratify_by else None

        train_df, test_df = train_test_split(
            self.df,
            test_size=test_size,
            random_state=random_state,
            stratify=stratify
        )

        logger.info(f"✂️  Split data:")
        logger.info(f"   - Train: {len(train_df):,} ({len(train_df)/len(self.df)*100:.1f}%)")
        logger.info(f"   - Test:  {len(test_df):,} ({len(test_df)/len(self.df)*100:.1f}%)")

        return train_df, test_df

    def get_cleaning_summary(self) -> Dict:
        """Get summary of cleaning operations."""
        return {
            'original_count': self.original_count,
            'final_count': len(self.df),
            'removed_count': self.original_count - len(self.df),
            'removal_percentage': (self.original_count - len(self.df)) / self.original_count * 100,
            'cleaning_steps': self.cleaning_log,
            'features_created': [
                'amount_abs',
                'is_credit_note',
                'log_amount',
                'analytic_parsed',
                'analytic_account_ids',
                'primary_analytic_account_id',
                'supplier_product_key',
                'full_text'
            ]
        }


def create_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create feature matrix for ML training.

    This prepares numerical and categorical features for scikit-learn models.

    Args:
        df: Cleaned DataFrame

    Returns:
        DataFrame with ML-ready features
    """
    features = df.copy()

    # Numerical features
    numerical_cols = ['quantity', 'price_unit', 'amount_abs', 'log_amount']

    # Categorical features (will be encoded)
    categorical_cols = [
        'supplier_id',
        'product_id',
        'product_category',
        'is_credit_note'
    ]

    # Target variable
    target_col = 'account_id'

    # Keep only relevant columns
    keep_cols = numerical_cols + categorical_cols + [target_col]
    keep_cols = [col for col in keep_cols if col in features.columns]

    features = features[keep_cols]

    # Fill remaining nulls with 0 (for numerical) or 'UNKNOWN' (for categorical)
    for col in numerical_cols:
        if col in features.columns:
            features[col] = features[col].fillna(0)

    for col in categorical_cols:
        if col in features.columns:
            features[col] = features[col].fillna('UNKNOWN')

    logger.info(f"🔢 Created feature matrix: {features.shape}")

    return features


def main():
    """Main execution."""
    print("=" * 80)
    print("DATA CLEANING")
    print("=" * 80)
    print()

    # Load validated data
    data_file = "/app/training/data/historical_invoice_lines_7years.csv"
    print(f"📂 Loading: {data_file}")

    try:
        df = pd.read_csv(data_file)
        print(f"✅ Loaded {len(df):,} records")
    except FileNotFoundError:
        print(f"❌ File not found: {data_file}")
        return

    # Clean data
    cleaner = DataCleaner(df)
    df_cleaned = cleaner.clean_all()

    # Split train/test
    train_df, test_df = cleaner.split_train_test(
        test_size=0.2,
        random_state=42,
        stratify_by='account_id'
    )

    # Save cleaned data
    output_dir = "/app/training/data"
    train_file = f"{output_dir}/train_data.csv"
    test_file = f"{output_dir}/test_data.csv"
    full_file = f"{output_dir}/cleaned_data.csv"

    train_df.to_csv(train_file, index=False)
    test_df.to_csv(test_file, index=False)
    df_cleaned.to_csv(full_file, index=False)

    print(f"\n💾 Saved cleaned data:")
    print(f"   - Full: {full_file}")
    print(f"   - Train: {train_file}")
    print(f"   - Test: {test_file}")

    # Create feature matrix for ML
    feature_matrix = create_feature_matrix(df_cleaned)
    feature_file = f"{output_dir}/feature_matrix.csv"
    feature_matrix.to_csv(feature_file, index=False)
    print(f"   - Features: {feature_file}")

    # Save cleaning summary
    summary = cleaner.get_cleaning_summary()
    summary_file = f"{output_dir}/cleaning_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"   - Summary: {summary_file}")

    # Print summary
    print("\n" + "=" * 80)
    print("CLEANING SUMMARY")
    print("=" * 80)
    print(f"✅ Original records: {summary['original_count']:,}")
    print(f"✅ Final records: {summary['final_count']:,}")
    print(f"🗑️  Removed: {summary['removed_count']:,} ({summary['removal_percentage']:.2f}%)")
    print(f"🔧 Features created: {len(summary['features_created'])}")
    print()
    print("🎯 Next step: Run train_embeddings.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
