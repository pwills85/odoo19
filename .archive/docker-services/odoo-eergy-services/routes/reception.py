"""
DTE Reception Routes
====================

FastAPI endpoints for receiving and processing DTEs from suppliers.

Based on Odoo 18: l10n_cl_fe/models/mail_dte.py
"""

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List, Dict, Optional
import logging
from datetime import datetime

from clients.imap_client import IMAPClient
from clients.sii_soap_client import SIISoapClient
from parsers.dte_parser import DTEParser
from validators.received_dte_validator import ReceivedDTEValidator, ReceivedDTEBusinessValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reception", tags=["DTE Reception"])


# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class IMAPConfig(BaseModel):
    """IMAP configuration for email reception."""
    host: str
    port: Optional[int] = 993
    user: str
    password: str
    use_ssl: bool = True
    sender_filter: Optional[str] = None
    unread_only: bool = True


class SIIDownloadRequest(BaseModel):
    """Request to download DTEs from SII."""
    rut_receptor: str
    dte_type: Optional[str] = None
    fecha_desde: Optional[str] = None


class CommercialResponseRequest(BaseModel):
    """Request to send commercial response."""
    dte_type: str
    folio: str
    emisor_rut: str
    receptor_rut: str
    response_code: str  # '0'=Accept, '1'=Reject, '2'=Claim
    reason: Optional[str] = None


class DTEReceptionResponse(BaseModel):
    """Response with received DTEs."""
    success: bool
    dtes: List[Dict]
    count: int
    errors: List[str] = []


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@router.post("/check_inbox", response_model=DTEReceptionResponse)
async def check_inbox(config: IMAPConfig, company_rut: str):
    """
    Check email inbox for received DTEs.

    This endpoint:
    1. Connects to IMAP server
    2. Downloads emails with DTE attachments
    3. Parses XML DTEs
    4. Validates DTEs
    5. Returns valid DTEs to Odoo

    Args:
        config: IMAP configuration
        company_rut: Company RUT (to validate we're the receptor)

    Returns:
        DTEReceptionResponse with list of valid DTEs
    """
    logger.info(f"Checking inbox for company RUT: {company_rut}")

    try:
        # 1. Connect to IMAP
        client = IMAPClient(
            host=config.host,
            port=config.port,
            user=config.user,
            password=config.password,
            use_ssl=config.use_ssl
        )

        if not client.connect():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to connect to email server"
            )

        # 2. Fetch DTE emails
        emails = client.fetch_dte_emails(
            sender_filter=config.sender_filter,
            unread_only=config.unread_only,
            limit=100
        )

        logger.info(f"Found {len(emails)} emails with DTEs")

        # 3. Process each email
        valid_dtes = []
        errors = []

        parser = DTEParser()
        validator = ReceivedDTEValidator()
        business_validator = ReceivedDTEBusinessValidator(company_rut)

        for email_data in emails:
            for attachment in email_data['attachments']:
                try:
                    # Parse DTE
                    parsed_dte = parser.parse(attachment['content'])

                    # Structural validation
                    is_valid, val_errors, val_warnings = validator.validate(parsed_dte)

                    if not is_valid:
                        logger.warning(f"DTE validation failed: {val_errors}")
                        errors.append({
                            'folio': parsed_dte.get('folio'),
                            'errors': val_errors
                        })
                        continue

                    # Business validation
                    is_valid_biz, biz_errors, biz_warnings = business_validator.validate(parsed_dte)

                    if not is_valid_biz:
                        logger.warning(f"Business validation failed: {biz_errors}")
                        errors.append({
                            'folio': parsed_dte.get('folio'),
                            'errors': biz_errors
                        })
                        continue

                    # Add metadata
                    parsed_dte['email_id'] = email_data['email_id']
                    parsed_dte['received_from'] = email_data['from']
                    parsed_dte['received_date'] = email_data['date']
                    parsed_dte['validation_warnings'] = val_warnings + biz_warnings

                    valid_dtes.append(parsed_dte)

                    # Mark email as read
                    client.mark_as_read(email_data['email_id'])

                except Exception as e:
                    logger.error(f"Error processing DTE: {e}")
                    errors.append({
                        'error': str(e),
                        'email_id': email_data.get('email_id')
                    })

        # Disconnect
        client.disconnect()

        logger.info(f"Processed {len(valid_dtes)} valid DTEs, {len(errors)} errors")

        return DTEReceptionResponse(
            success=True,
            dtes=valid_dtes,
            count=len(valid_dtes),
            errors=[str(e) for e in errors]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Inbox check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check inbox: {str(e)}"
        )


@router.post("/download_sii", response_model=DTEReceptionResponse)
async def download_from_sii(request: SIIDownloadRequest, company_rut: str):
    """
    Download DTEs directly from SII using GetDTE SOAP method.

    This endpoint:
    1. Calls SII GetDTE SOAP service
    2. Downloads DTEs sent to our company
    3. Parses and validates DTEs
    4. Returns valid DTEs to Odoo

    Args:
        request: SII download parameters
        company_rut: Company RUT (to validate)

    Returns:
        DTEReceptionResponse with list of downloaded DTEs
    """
    logger.info(f"Downloading DTEs from SII for RUT: {request.rut_receptor}")

    try:
        # Validate RUT matches company
        if request.rut_receptor.replace('.', '').replace('-', '').upper() != \
           company_rut.replace('.', '').replace('-', '').upper():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Receptor RUT does not match company RUT"
            )

        # 1. Initialize SII client
        # Determine environment (sandbox vs production)
        import os
        sii_env = os.getenv('SII_ENVIRONMENT', 'sandbox')

        if sii_env == 'sandbox':
            wsdl_url = 'https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl'
        else:
            wsdl_url = 'https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl'

        sii_client = SIISoapClient(wsdl_url=wsdl_url, timeout=60)

        # 2. Download DTEs from SII
        result = sii_client.get_received_dte(
            rut_receptor=request.rut_receptor,
            dte_type=request.dte_type,
            fecha_desde=request.fecha_desde
        )

        if not result['success']:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to download from SII: {result.get('errors')}"
            )

        # 3. Parse and validate each DTE
        valid_dtes = []
        errors = []

        parser = DTEParser()
        validator = ReceivedDTEValidator()
        business_validator = ReceivedDTEBusinessValidator(company_rut)

        for dte_info in result['dtes']:
            try:
                # Parse XML
                if not dte_info.get('xml'):
                    continue

                parsed_dte = parser.parse(dte_info['xml'])

                # Structural validation
                is_valid, val_errors, val_warnings = validator.validate(parsed_dte)

                if not is_valid:
                    errors.append({
                        'folio': parsed_dte.get('folio'),
                        'errors': val_errors
                    })
                    continue

                # Business validation
                is_valid_biz, biz_errors, biz_warnings = business_validator.validate(parsed_dte)

                if not is_valid_biz:
                    errors.append({
                        'folio': parsed_dte.get('folio'),
                        'errors': biz_errors
                    })
                    continue

                # Add SII metadata
                parsed_dte['sii_estado'] = dte_info.get('estado')
                parsed_dte['downloaded_from_sii'] = True
                parsed_dte['download_date'] = datetime.now().isoformat()
                parsed_dte['validation_warnings'] = val_warnings + biz_warnings

                valid_dtes.append(parsed_dte)

            except Exception as e:
                logger.error(f"Error processing SII DTE: {e}")
                errors.append({
                    'error': str(e),
                    'folio': dte_info.get('folio')
                })

        logger.info(f"Downloaded {len(valid_dtes)} valid DTEs from SII")

        return DTEReceptionResponse(
            success=True,
            dtes=valid_dtes,
            count=len(valid_dtes),
            errors=[str(e) for e in errors]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SII download failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download from SII: {str(e)}"
        )


@router.post("/send_response")
async def send_commercial_response(request: CommercialResponseRequest):
    """
    Send commercial response to SII (Accept/Reject/Claim).

    Response codes:
    - '0': Accept document
    - '1': Reject document
    - '2': Claim - Accept with observations

    Args:
        request: Commercial response data

    Returns:
        Success status
    """
    logger.info(f"Sending commercial response for DTE {request.dte_type}-{request.folio}")

    try:
        # Validate response code
        if request.response_code not in ['0', '1', '2']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid response code. Must be '0', '1', or '2'"
            )

        # Initialize SII client
        import os
        sii_env = os.getenv('SII_ENVIRONMENT', 'sandbox')

        if sii_env == 'sandbox':
            wsdl_url = 'https://maullin.sii.cl/DTEWS/DTEServiceTest.asmx?wsdl'
        else:
            wsdl_url = 'https://palena.sii.cl/DTEWS/DTEService.asmx?wsdl'

        sii_client = SIISoapClient(wsdl_url=wsdl_url, timeout=60)

        # Build response XML (simplified - full implementation would use XML templates)
        response_xml = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
        <RespuestaDTE version="1.0">
            <Resultado>
                <Caratula>
                    <RutResponde>{request.receptor_rut}</RutResponde>
                    <RutRecibe>{request.emisor_rut}</RutRecibe>
                    <TmstFirmaResp>{datetime.now().isoformat()}</TmstFirmaResp>
                </Caratula>
                <RecepcionEnvio>
                    <TipoDTE>{request.dte_type}</TipoDTE>
                    <Folio>{request.folio}</Folio>
                    <CodRespuesta>{request.response_code}</CodRespuesta>
                    <Recinto>{request.reason or ''}</Recinto>
                </RecepcionEnvio>
            </Resultado>
        </RespuestaDTE>
        """

        # Send to SII (using EnvioRecepcion method)
        # Note: This is simplified - real implementation needs digital signature
        response = sii_client.client.service.EnvioRecepcion(
            rutEmisor=request.receptor_rut,
            dvEmisor=sii_client._extract_dv(request.receptor_rut),
            archivo=response_xml
        )

        logger.info(f"Commercial response sent successfully")

        return {
            'success': True,
            'response_code': request.response_code,
            'track_id': getattr(response, 'TRACKID', None)
        }

    except Exception as e:
        logger.error(f"Failed to send commercial response: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send response: {str(e)}"
        )


@router.post("/parse_dte")
async def parse_dte_xml(xml_content: str):
    """
    Parse DTE XML and return structured data.

    Utility endpoint for manual DTE parsing.

    Args:
        xml_content: DTE XML as string

    Returns:
        Parsed DTE data
    """
    try:
        parser = DTEParser()
        parsed = parser.parse(xml_content)

        return {
            'success': True,
            'data': parsed
        }

    except Exception as e:
        logger.error(f"Parse failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse DTE: {str(e)}"
        )
