# -*- coding: utf-8 -*-
"""
PDF417 Barcode Generator for Chilean DTE
==========================================

Professional PDF417 barcode generator for TED (Timbre Electrónico Digital)
used in Chilean Electronic Tax Documents (DTE).

SII Requirements (Resolución 80/2014):
- Barcode type: PDF417
- Error correction level: 5 (highest)
- Max width: 400 pixels
- Encoding: UTF-8
- Format: PNG base64-encoded

Technical Stack:
- pdf417: Python library for PDF417 generation
- Pillow (PIL): Image processing and PNG export
- base64: Encoding for web/PDF embedding

Usage Example:
    generator = PDF417Generator()
    barcode_b64 = generator.generate_pdf417(ted_xml_string)

    # In QWeb template:
    <img t-att-src="'data:image/png;base64,%s' % barcode_b64"/>

Author: EERGYGROUP - Ing. Pedro Troncoso Willz
License: LGPL-3
Version: 19.0.1.0.0
Date: 2025-11-04
"""

import logging
import base64
from io import BytesIO

try:
    import pdf417
    PDF417_AVAILABLE = True
except ImportError:
    PDF417_AVAILABLE = False

try:
    from PIL import Image, ImageDraw
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

_logger = logging.getLogger(__name__)


class PDF417Generator:
    """
    Professional PDF417 barcode generator for Chilean DTE TED.

    Generates PDF417 2D barcodes compliant with SII requirements for
    Timbre Electrónico Digital (TED) in Chilean electronic invoicing.

    SII Compliance:
    ---------------
    - Error correction: Level 5 (30% data recovery)
    - Max width: 400 pixels
    - Encoding: UTF-8
    - Format: PNG base64-encoded
    - Color: Black barcode on white background

    Attributes:
        error_correction_level (int): SII-required level 5
        max_width_px (int): Maximum barcode width (400px)
        module_width (int): Width of each barcode module in pixels
        module_height (int): Height of each barcode module in pixels

    Example:
        >>> generator = PDF417Generator()
        >>> ted_xml = "<TED>...</TED>"
        >>> barcode = generator.generate_pdf417(ted_xml)
        >>> print(len(barcode))  # base64 string length
        5432
    """

    # SII-compliant configuration
    ERROR_CORRECTION_LEVEL = 5  # Highest (30% recovery) - SII requirement
    MAX_WIDTH_PX = 400          # Maximum width in pixels
    MODULE_WIDTH = 2            # Width of each module (bar) in pixels
    MODULE_HEIGHT = 6           # Height of each module in pixels
    COLUMNS = 8                 # Number of data columns (optimal for TED)

    def __init__(self):
        """
        Initialize PDF417 generator.

        Raises:
            ImportError: If pdf417 or Pillow libraries are not installed
        """
        if not PDF417_AVAILABLE:
            raise ImportError(
                "pdf417 library is not installed. "
                "Install with: pip install pdf417"
            )

        if not PIL_AVAILABLE:
            raise ImportError(
                "Pillow library is not installed. "
                "Install with: pip install Pillow"
            )

        _logger.debug("PDF417Generator initialized (SII-compliant configuration)")

    def generate_pdf417(self, ted_xml):
        """
        Generate PDF417 barcode from TED XML string.

        Process:
        1. Validate TED XML format
        2. Encode to PDF417 matrix (error correction level 5)
        3. Render matrix as PNG image
        4. Encode image to base64

        Args:
            ted_xml (str): TED XML content (UTF-8 encoded)
                          Example: "<TED version='1.0'>...</TED>"

        Returns:
            str: Base64-encoded PNG image, or False on error
                 Format: "iVBORw0KGgoAAAANSUhEUgAA..."

        Raises:
            ValueError: If TED XML is empty or invalid format

        Example:
            >>> ted = "<TED version='1.0'><DD><RE>12345678-9</RE>...</DD></TED>"
            >>> b64 = generator.generate_pdf417(ted)
            >>> # Use in template: data:image/png;base64,{b64}

        SII Compliance:
            - Error correction: 30% (level 5)
            - Max width: 400px
            - Encoding: UTF-8
        """
        if not ted_xml:
            _logger.error("TED XML is empty - cannot generate PDF417")
            return False

        # Validate TED XML (basic check)
        if not self.validate_ted_xml(ted_xml):
            _logger.error("Invalid TED XML format - cannot generate PDF417")
            return False

        try:
            # Step 1: Encode TED XML to PDF417 matrix
            # security_level: 0-8, SII requires 5 (30% recovery)
            # columns: 1-30, optimal for TED is 6-10
            _logger.debug(f"Encoding TED XML to PDF417 (length: {len(ted_xml)} chars)")

            codes = pdf417.encode(
                ted_xml,
                security_level=self.ERROR_CORRECTION_LEVEL,
                columns=self.COLUMNS
            )

            if not codes:
                _logger.error("PDF417 encoding failed - empty result")
                return False

            _logger.debug(f"PDF417 matrix generated: {len(codes)} rows x {len(codes[0])} cols")

            # Step 2: Render matrix as PNG image
            image = self._render_barcode_image(codes)

            if not image:
                _logger.error("Failed to render PDF417 as image")
                return False

            # Step 3: Convert image to base64
            base64_image = self._image_to_base64(image)

            if not base64_image:
                _logger.error("Failed to convert image to base64")
                return False

            _logger.info(
                f"PDF417 generated successfully: "
                f"{image.width}x{image.height}px, "
                f"{len(base64_image)} bytes (base64)"
            )

            return base64_image

        except Exception as e:
            _logger.error(f"Error generating PDF417: {e}", exc_info=True)
            return False

    def validate_ted_xml(self, ted_xml):
        """
        Validate TED XML format (basic validation).

        Checks:
        - Not empty
        - Contains <TED> tags
        - Reasonable length (< 10KB)
        - Valid UTF-8 encoding

        Args:
            ted_xml (str): TED XML string to validate

        Returns:
            bool: True if valid format, False otherwise

        Note:
            This is a BASIC validation. Full XML schema validation
            should be done by XSDValidator in l10n_cl_dte base module.

        Example:
            >>> valid_ted = "<TED version='1.0'>...</TED>"
            >>> generator.validate_ted_xml(valid_ted)
            True
            >>> invalid_ted = "not xml"
            >>> generator.validate_ted_xml(invalid_ted)
            False
        """
        if not ted_xml or not isinstance(ted_xml, str):
            _logger.warning("TED XML is empty or not a string")
            return False

        # Check minimum length
        if len(ted_xml) < 50:
            _logger.warning(f"TED XML too short: {len(ted_xml)} chars (min 50)")
            return False

        # Check maximum length (prevent DoS)
        if len(ted_xml) > 10240:  # 10KB max
            _logger.warning(f"TED XML too long: {len(ted_xml)} chars (max 10KB)")
            return False

        # Check for TED tags
        if '<TED' not in ted_xml or '</TED>' not in ted_xml:
            _logger.warning("TED XML missing <TED> tags")
            return False

        # Check UTF-8 encoding
        try:
            ted_xml.encode('utf-8')
        except UnicodeEncodeError as e:
            _logger.warning(f"TED XML contains invalid UTF-8: {e}")
            return False

        return True

    def _render_barcode_image(self, codes):
        """
        Render PDF417 matrix as PIL Image (PNG).

        Args:
            codes (list): 2D matrix from pdf417.encode()
                         Example: [[1,0,1,1], [0,1,0,1], ...]

        Returns:
            PIL.Image: PNG image, or None on error

        Rendering:
            - Black modules (1) on white background (0)
            - Module width: 2px
            - Module height: 6px
            - White margin: 10px on all sides

        SII Compliance:
            - Max width: 400px (enforced)
            - Format: PNG
            - Color: Black (#000000) on white (#FFFFFF)
        """
        if not codes or not codes[0]:
            _logger.error("Invalid PDF417 matrix (empty)")
            return None

        try:
            rows = len(codes)
            cols = len(codes[0])

            # Calculate image dimensions
            margin = 10  # White margin (pixels)
            img_width = (cols * self.MODULE_WIDTH) + (2 * margin)
            img_height = (rows * self.MODULE_HEIGHT) + (2 * margin)

            # Enforce max width (SII requirement)
            if img_width > self.MAX_WIDTH_PX:
                scale = self.MAX_WIDTH_PX / img_width
                img_width = self.MAX_WIDTH_PX
                img_height = int(img_height * scale)
                _logger.debug(f"Scaled barcode to {img_width}x{img_height}px (max 400px)")

            # Create white background
            image = Image.new('RGB', (img_width, img_height), color='white')
            draw = ImageDraw.Draw(image)

            # Draw black modules
            for row_idx, row in enumerate(codes):
                for col_idx, module in enumerate(row):
                    if module == 1:  # Black module
                        x = margin + (col_idx * self.MODULE_WIDTH)
                        y = margin + (row_idx * self.MODULE_HEIGHT)

                        # Draw filled rectangle (black)
                        draw.rectangle(
                            [
                                x, y,
                                x + self.MODULE_WIDTH - 1,
                                y + self.MODULE_HEIGHT - 1
                            ],
                            fill='black'
                        )

            _logger.debug(f"Barcode rendered: {img_width}x{img_height}px")
            return image

        except Exception as e:
            _logger.error(f"Error rendering barcode image: {e}", exc_info=True)
            return None

    def _image_to_base64(self, image):
        """
        Convert PIL Image to base64-encoded PNG.

        Args:
            image (PIL.Image): Image object to convert

        Returns:
            str: Base64-encoded PNG string (without data URI prefix)
                 Example: "iVBORw0KGgoAAAANSUhEUgAA..."

        Note:
            Returns base64 string ONLY (no "data:image/png;base64," prefix).
            Prefix should be added in QWeb template.

        Example:
            >>> img = Image.new('RGB', (100, 100), 'white')
            >>> b64 = generator._image_to_base64(img)
            >>> # In template: data:image/png;base64,{b64}
        """
        if not image:
            return None

        try:
            # Save image to BytesIO buffer
            buffer = BytesIO()
            image.save(buffer, format='PNG', optimize=True)
            buffer.seek(0)

            # Encode to base64
            img_bytes = buffer.read()
            base64_str = base64.b64encode(img_bytes).decode('utf-8')

            _logger.debug(f"Image converted to base64: {len(base64_str)} chars")
            return base64_str

        except Exception as e:
            _logger.error(f"Error converting image to base64: {e}", exc_info=True)
            return None

    def get_barcode_dimensions(self, ted_xml):
        """
        Calculate barcode dimensions without generating full image.

        Useful for pre-allocating space in PDF layouts.

        Args:
            ted_xml (str): TED XML content

        Returns:
            tuple: (width, height) in pixels, or (0, 0) on error

        Example:
            >>> ted = "<TED>...</TED>"
            >>> width, height = generator.get_barcode_dimensions(ted)
            >>> print(f"Barcode size: {width}x{height}px")
            Barcode size: 360x80px
        """
        if not ted_xml or not self.validate_ted_xml(ted_xml):
            return (0, 0)

        try:
            codes = pdf417.encode(
                ted_xml,
                security_level=self.ERROR_CORRECTION_LEVEL,
                columns=self.COLUMNS
            )

            if not codes:
                return (0, 0)

            rows = len(codes)
            cols = len(codes[0])

            margin = 10
            width = (cols * self.MODULE_WIDTH) + (2 * margin)
            height = (rows * self.MODULE_HEIGHT) + (2 * margin)

            # Enforce max width
            if width > self.MAX_WIDTH_PX:
                scale = self.MAX_WIDTH_PX / width
                width = self.MAX_WIDTH_PX
                height = int(height * scale)

            return (width, height)

        except Exception as e:
            _logger.error(f"Error calculating dimensions: {e}")
            return (0, 0)


# ══════════════════════════════════════════════════════════════════════════════
# Module-level convenience function (optional)
# ══════════════════════════════════════════════════════════════════════════════

def generate_ted_pdf417(ted_xml):
    """
    Convenience function to generate PDF417 from TED XML.

    Wrapper around PDF417Generator.generate_pdf417() for simpler usage.

    Args:
        ted_xml (str): TED XML content

    Returns:
        str: Base64-encoded PNG image, or False on error

    Example:
        >>> from l10n_cl_dte_enhanced.libs import pdf417_generator
        >>> barcode = pdf417_generator.generate_ted_pdf417(ted_xml)
    """
    try:
        generator = PDF417Generator()
        return generator.generate_pdf417(ted_xml)
    except Exception as e:
        _logger.error(f"Error in generate_ted_pdf417: {e}")
        return False
