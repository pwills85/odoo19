"""
IMAP Client for DTE Reception
==============================

Downloads DTEs received via email from SII.

Based on Odoo 18: l10n_cl_fe/models/mail_dte.py (450 LOC)
"""

import imaplib
import email
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import os
import xml.etree.ElementTree as ET
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IMAPClient:
    """IMAP client for downloading DTEs from email."""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        user: str = None,
        password: str = None,
        use_ssl: bool = True
    ):
        """
        Initialize IMAP client.

        Args:
            host: IMAP server host (default from env)
            port: IMAP server port (default 993 for SSL, 143 for non-SSL)
            user: Email username
            password: Email password
            use_ssl: Use SSL/TLS connection (default True)
        """
        self.host = host or os.getenv('IMAP_HOST', 'imap.gmail.com')
        self.port = port or (993 if use_ssl else 143)
        self.user = user or os.getenv('IMAP_USER')
        self.password = password or os.getenv('IMAP_PASSWORD')
        self.use_ssl = use_ssl
        self.connection = None

    def connect(self) -> bool:
        """
        Connect to IMAP server.

        Returns:
            True if connected, False otherwise
        """
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)

            # Login
            self.connection.login(self.user, self.password)
            logger.info(f"✅ Connected to IMAP server: {self.host}")
            return True

        except imaplib.IMAP4.error as e:
            logger.error(f"❌ IMAP connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error connecting to IMAP: {e}")
            return False

    def disconnect(self):
        """Disconnect from IMAP server."""
        if self.connection:
            try:
                self.connection.close()
                self.connection.logout()
                logger.info("Disconnected from IMAP server")
            except:
                pass

    def fetch_dte_emails(
        self,
        folder: str = 'INBOX',
        sender_filter: str = None,
        unread_only: bool = True,
        limit: int = 100
    ) -> List[Dict]:
        """
        Fetch DTE emails from mailbox.

        Args:
            folder: IMAP folder to search (default 'INBOX')
            sender_filter: Filter by sender email (e.g., 'dte@sii.cl')
            unread_only: Only fetch unread emails (default True)
            limit: Maximum number of emails to fetch (default 100)

        Returns:
            List of dicts with email data:
                - email_id: Email ID
                - from: Sender email
                - subject: Email subject
                - date: Received date
                - attachments: List of XML attachments
        """
        if not self.connection:
            if not self.connect():
                return []

        try:
            # Select folder
            self.connection.select(folder)

            # Build search criteria
            search_criteria = []

            if unread_only:
                search_criteria.append('UNSEEN')

            if sender_filter:
                search_criteria.append(f'FROM "{sender_filter}"')

            # Search for DTE emails (typically from SII)
            if not sender_filter:
                # Default: search for emails with XML attachments (DTE indicator)
                search_criteria.append('SUBJECT "DTE"')

            # Execute search
            criteria_str = ' '.join(search_criteria) if search_criteria else 'ALL'
            status, message_ids = self.connection.search(None, criteria_str)

            if status != 'OK':
                logger.warning(f"Search failed: {status}")
                return []

            # Get email IDs
            email_ids = message_ids[0].split()

            if not email_ids:
                logger.info("No DTE emails found")
                return []

            # Limit results
            email_ids = email_ids[-limit:] if len(email_ids) > limit else email_ids

            logger.info(f"📧 Found {len(email_ids)} DTE emails")

            # Fetch emails
            dte_emails = []
            for email_id in email_ids:
                email_data = self._fetch_email(email_id)
                if email_data:
                    dte_emails.append(email_data)

            return dte_emails

        except Exception as e:
            logger.error(f"❌ Error fetching emails: {e}")
            return []

    def _fetch_email(self, email_id: bytes) -> Optional[Dict]:
        """
        Fetch single email and extract DTE data.

        Args:
            email_id: Email ID from IMAP

        Returns:
            Dict with email data or None if error
        """
        try:
            # Fetch email
            status, msg_data = self.connection.fetch(email_id, '(RFC822)')

            if status != 'OK':
                return None

            # Parse email
            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)

            # Extract metadata
            from_addr = email.utils.parseaddr(email_message.get('From'))[1]
            subject = email_message.get('Subject', '')
            date_str = email_message.get('Date', '')

            # Parse date
            try:
                date = email.utils.parsedate_to_datetime(date_str)
            except:
                date = datetime.now()

            # Extract XML attachments (DTEs)
            attachments = self._extract_xml_attachments(email_message)

            if not attachments:
                logger.debug(f"Email {email_id.decode()} has no XML attachments")
                return None

            return {
                'email_id': email_id.decode(),
                'from': from_addr,
                'subject': subject,
                'date': date.isoformat(),
                'attachments': attachments
            }

        except Exception as e:
            logger.error(f"❌ Error fetching email {email_id}: {e}")
            return None

    def _extract_xml_attachments(self, email_message) -> List[Dict]:
        """
        Extract XML attachments from email.

        Args:
            email_message: Email message object

        Returns:
            List of dicts with attachment data:
                - filename: Attachment filename
                - content: XML content (string)
                - size: File size in bytes
        """
        attachments = []

        for part in email_message.walk():
            # Skip multipart containers
            if part.get_content_maintype() == 'multipart':
                continue

            # Check if attachment
            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()

            # Only process XML files
            if not filename or not filename.lower().endswith('.xml'):
                continue

            # Get content
            content = part.get_payload(decode=True)

            if not content:
                continue

            # Decode content
            try:
                content_str = content.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    content_str = content.decode('latin-1')
                except:
                    logger.warning(f"Could not decode XML: {filename}")
                    continue

            # Validate it's a DTE XML (has DTE tag)
            if not self._is_dte_xml(content_str):
                logger.debug(f"XML {filename} is not a valid DTE")
                continue

            attachments.append({
                'filename': filename,
                'content': content_str,
                'size': len(content)
            })

            logger.info(f"📎 Extracted DTE XML: {filename} ({len(content)} bytes)")

        return attachments

    def _is_dte_xml(self, xml_content: str) -> bool:
        """
        Check if XML content is a valid DTE.

        Args:
            xml_content: XML content as string

        Returns:
            True if valid DTE XML, False otherwise
        """
        try:
            # Parse XML
            root = ET.fromstring(xml_content)

            # Check for DTE namespace and tags
            # Valid DTE should have: DTE, Documento, Encabezado, etc.
            dte_tags = ['DTE', 'Documento', 'EnvioDTE', 'SetDTE']

            # Check if root or any child has DTE-related tags
            if any(tag in root.tag for tag in dte_tags):
                return True

            # Check children
            for child in root:
                if any(tag in child.tag for tag in dte_tags):
                    return True

            return False

        except ET.ParseError:
            return False
        except Exception:
            return False

    def mark_as_read(self, email_id: str) -> bool:
        """
        Mark email as read.

        Args:
            email_id: Email ID

        Returns:
            True if successful, False otherwise
        """
        if not self.connection:
            return False

        try:
            self.connection.store(email_id.encode(), '+FLAGS', '\\Seen')
            logger.info(f"✅ Marked email {email_id} as read")
            return True
        except Exception as e:
            logger.error(f"❌ Error marking email as read: {e}")
            return False

    def move_to_folder(self, email_id: str, folder: str) -> bool:
        """
        Move email to another folder.

        Args:
            email_id: Email ID
            folder: Destination folder name

        Returns:
            True if successful, False otherwise
        """
        if not self.connection:
            return False

        try:
            # Copy to destination folder
            self.connection.copy(email_id.encode(), folder)

            # Delete from current folder
            self.connection.store(email_id.encode(), '+FLAGS', '\\Deleted')
            self.connection.expunge()

            logger.info(f"✅ Moved email {email_id} to folder {folder}")
            return True

        except Exception as e:
            logger.error(f"❌ Error moving email: {e}")
            return False

    def get_dte_summary(self, xml_content: str) -> Dict:
        """
        Extract summary information from DTE XML.

        Args:
            xml_content: DTE XML content

        Returns:
            Dict with DTE summary:
                - dte_type: Document type (33, 34, 52, 56, 61, etc.)
                - folio: Document folio number
                - rut_emisor: Issuer RUT
                - rut_receptor: Receiver RUT
                - fecha_emision: Emission date
                - monto_total: Total amount
        """
        try:
            root = ET.fromstring(xml_content)

            # Navigate XML structure (depends on DTE format)
            # Typical structure: SetDTE > DTE > Documento > Encabezado

            # Find Documento
            documento = None
            for elem in root.iter():
                if 'Documento' in elem.tag:
                    documento = elem
                    break

            if not documento:
                return {}

            # Find Encabezado
            encabezado = documento.find('.//{*}Encabezado') or documento.find('.//Encabezado')

            if not encabezado:
                return {}

            # Extract IdDoc
            id_doc = encabezado.find('.//{*}IdDoc') or encabezado.find('.//IdDoc')

            # Extract Emisor
            emisor = encabezado.find('.//{*}Emisor') or encabezado.find('.//Emisor')

            # Extract Receptor
            receptor = encabezado.find('.//{*}Receptor') or encabezado.find('.//Receptor')

            # Extract Totales
            totales = encabezado.find('.//{*}Totales') or encabezado.find('.//Totales')

            summary = {}

            if id_doc is not None:
                tipo_dte = id_doc.find('.//{*}TipoDTE') or id_doc.find('.//TipoDTE')
                folio = id_doc.find('.//{*}Folio') or id_doc.find('.//Folio')
                fecha = id_doc.find('.//{*}FchEmis') or id_doc.find('.//FchEmis')

                if tipo_dte is not None:
                    summary['dte_type'] = tipo_dte.text

                if folio is not None:
                    summary['folio'] = folio.text

                if fecha is not None:
                    summary['fecha_emision'] = fecha.text

            if emisor is not None:
                rut_emisor = emisor.find('.//{*}RUTEmisor') or emisor.find('.//RUTEmisor')
                if rut_emisor is not None:
                    summary['rut_emisor'] = rut_emisor.text

            if receptor is not None:
                rut_receptor = receptor.find('.//{*}RUTRecep') or receptor.find('.//RUTRecep')
                if rut_receptor is not None:
                    summary['rut_receptor'] = rut_receptor.text

            if totales is not None:
                monto_total = totales.find('.//{*}MntTotal') or totales.find('.//MntTotal')
                if monto_total is not None:
                    summary['monto_total'] = monto_total.text

            return summary

        except Exception as e:
            logger.error(f"❌ Error extracting DTE summary: {e}")
            return {}


def main():
    """Test IMAP client."""
    print("=" * 80)
    print("IMAP CLIENT - DTE RECEPTION TEST")
    print("=" * 80)
    print()

    # Initialize client
    client = IMAPClient()

    # Connect
    if not client.connect():
        print("❌ Failed to connect to IMAP server")
        print("   Check environment variables: IMAP_HOST, IMAP_USER, IMAP_PASSWORD")
        return

    try:
        # Fetch DTE emails
        print("📧 Fetching DTE emails...")
        emails = client.fetch_dte_emails(
            sender_filter='dte@sii.cl',  # Adjust for your environment
            unread_only=True,
            limit=10
        )

        print(f"\n✅ Found {len(emails)} DTE emails\n")

        # Process each email
        for idx, email_data in enumerate(emails, 1):
            print(f"Email {idx}:")
            print(f"  From: {email_data['from']}")
            print(f"  Subject: {email_data['subject']}")
            print(f"  Date: {email_data['date']}")
            print(f"  Attachments: {len(email_data['attachments'])}")

            # Process each attachment
            for att in email_data['attachments']:
                print(f"\n  📎 Attachment: {att['filename']} ({att['size']} bytes)")

                # Extract summary
                summary = client.get_dte_summary(att['content'])

                if summary:
                    print(f"     DTE Type: {summary.get('dte_type', 'N/A')}")
                    print(f"     Folio: {summary.get('folio', 'N/A')}")
                    print(f"     Emisor: {summary.get('rut_emisor', 'N/A')}")
                    print(f"     Receptor: {summary.get('rut_receptor', 'N/A')}")
                    print(f"     Monto: {summary.get('monto_total', 'N/A')}")
                    print(f"     Fecha: {summary.get('fecha_emision', 'N/A')}")

            print()

        print("=" * 80)

    finally:
        client.disconnect()


if __name__ == '__main__':
    main()
