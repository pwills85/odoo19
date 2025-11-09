# Quick Start - Odoo Module Integration Testing

**Purpose**: Step-by-step guide to test the professional Odoo + DTE Service integration

**Time**: ~30 minutes
**Environment**: Development/Staging
**Status**: Ready to test

---

## Prerequisites

### 1. Services Running

```bash
# Verify all services are up
docker-compose ps

# Should show:
# - odoo (port 8169)
# - dte-service (port 8001)
# - ai-service (port 8002)
# - db (PostgreSQL)
# - redis
# - rabbitmq

# Check service health
docker-compose logs -f dte-service | grep "Application startup complete"
docker-compose logs -f ai-service | grep "Application startup complete"
```

### 2. Environment Variables

Verify `.env` file contains:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-xxx
JWT_SECRET_KEY=your-super-secret-key-min-32-chars

# Optional
DTE_SERVICE_API_KEY=your-secure-token
AI_SERVICE_API_KEY=your-secure-token
SII_ENVIRONMENT=sandbox
```

---

## Step 1: Update Odoo Module (5 min)

```bash
# Stop Odoo to update module
docker-compose stop odoo

# Update module
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -u l10n_cl_dte --stop-after-init

# Or install from scratch (if first time)
docker-compose exec odoo odoo -c /etc/odoo/odoo.conf -d odoo -i l10n_cl_dte --stop-after-init

# Start Odoo again
docker-compose start odoo

# Verify no errors
docker-compose logs odoo | tail -50
```

**Expected output**:
```
INFO odoo odoo.modules.loading: updating modules list
INFO odoo odoo.modules.loading: module l10n_cl_dte: loading objects
INFO odoo odoo.modules.registry: Registry loaded in X.XXs
```

---

## Step 2: Configure DTE Service Connection (5 min)

### In Odoo UI:

1. **Login**: http://localhost:8169
   - User: `admin`
   - Password: (set during installation)

2. **Navigate to Settings**:
   - Apps → Settings → Chilean DTE (or search "DTE")

3. **Configure DTE Service**:
   ```
   DTE Service URL: http://dte-service:8001
   DTE Service API Key: (if configured in .env)
   DTE Service Timeout: 60 seconds
   ```

4. **Save**

5. **Test Connection**:
   - Click "Test DTE Service Connection" button
   - Should show: ✅ "Service: OK | SII: available/unavailable"

---

## Step 3: Upload Test Certificate (5 min)

### Option A: Use Existing Test Certificate

If you have a test `.p12` certificate from SII:

1. **Navigate**: Accounting → Chilean DTE → Certificates

2. **Create Certificate**:
   - Name: `Test Certificate - Sandbox`
   - Company: (select your company)
   - Certificate File: (upload .p12 file)
   - Password: (enter certificate password)
   - Environment: `Sandbox (Maullin)`

3. **Save**

4. **Verify**: Status should show "Valid" with expiration date

### Option B: Use Demo Certificate (Development Only)

**⚠️ WARNING**: For development testing only, NOT for production

```bash
# Generate self-signed test certificate (development only)
cd /Users/pedro/Documents/odoo19/dte-service/tests/fixtures
openssl req -x509 -newkey rsa:2048 -keyout test_key.pem -out test_cert.pem -days 365 -nodes
openssl pkcs12 -export -out test_cert.p12 -inkey test_key.pem -in test_cert.pem -password pass:test123
```

Then upload `test_cert.p12` with password `test123`.

---

## Step 4: Upload Test CAF (5 min)

### Get CAF from SII Sandbox

1. **Login to Maullin**: https://maullin.sii.cl/

2. **Navigate**: Facturación Electrónica → Folios

3. **Request CAF**:
   - Document Type: `33` (Factura Electrónica)
   - Quantity: `10` folios
   - Download CAF XML file

### Upload to Odoo

1. **Navigate**: Accounting → Chilean DTE → CAF Files

2. **Create CAF**:
   - Name: `CAF DTE 33 - Test`
   - Company: (select your company)
   - DTE Type: `33 - Factura Electrónica`
   - CAF File: (upload .xml file from SII)

3. **Save**

4. **Verify**:
   - Status: `Active`
   - Available Folios: `10`
   - Start/End Folio: (should show range)

---

## Step 5: Create Test Invoice (3 min)

1. **Navigate**: Accounting → Customers → Invoices

2. **Create Invoice**:
   - Customer: (select or create)
   - Customer RUT: `12345678-9` (format: XXXXXXXX-X)
   - Invoice Date: (today)
   - Journal: (sales journal)

3. **Add Invoice Lines**:
   - Product: (any product)
   - Quantity: `1`
   - Unit Price: `10000` CLP
   - Tax: `IVA 19%`

4. **Total**: Should be `11,900 CLP` (10,000 + 1,900 IVA)

5. **Save** (Draft state)

---

## Step 6: Generate DTE - Happy Path (5 min)

### Post Invoice

1. Click **"Confirm"** button
2. Invoice state → `Posted`
3. New button appears: **"Generate DTE"** (primary button)

### Open DTE Wizard

1. Click **"Generate DTE"**

2. **Wizard displays**:
   ```
   ✅ Service: OK | SII: Available

   Invoice Information:
   - Invoice: INV/2025/0001
   - DTE Type: 33 - Factura Electrónica

   DTE Configuration:
   - Certificate: [Test Certificate - Sandbox] (auto-selected)
   - CAF: [CAF DTE 33 - Test] (auto-selected, shows available folios)
   - Environment: [x] Sandbox  [ ] Production

   Before generating DTE, ensure:
   - Invoice is posted and validated ✅
   - Digital certificate is valid ✅
   - CAF has available folios ✅
   - Customer RUT is correctly formatted ✅
   - All invoice lines have valid taxes ✅
   ```

3. **Review**: All checkmarks should be green

4. Click **"Generate DTE"** button

### Expected Result

**Success Notification** (green):
```
✅ DTE Sent Successfully

DTE sent to SII with Track ID: 123456789
Folio: 1
```

**Invoice Updated**:
- DTE Status bar: `Sent` or `Accepted`
- Smart buttons appear: "DTE XML", "DTE PDF"
- Chatter message: "DTE sent to SII (Track ID: 123456789, Folio: 1)"

**Invoice "DTE Information" Tab**:
- DTE Type: `33`
- DTE Folio: `1`
- Track ID: `123456789`
- Certificate: `Test Certificate - Sandbox`
- CAF: `CAF DTE 33 - Test`
- QR Code: (visual QR code displayed)
- XML: (expandable, shows signed XML)

---

## Step 7: Test Contingency Mode (5 min)

**Purpose**: Verify graceful degradation when DTE Service unavailable

### Simulate Service Unavailability

```bash
# Stop DTE Service
docker-compose stop dte-service
```

### Create Another Invoice

1. Follow **Step 5** to create another test invoice
2. Post invoice

### Open DTE Wizard

1. Click **"Generate DTE"**

2. **Wizard shows**:
   ```
   ⚠️ Service: Connection error
   ⚠️ Contingency Mode Active

   DTEs will be generated offline and sent when SII service recovers.
   ```

3. Select certificate/CAF/environment
4. Click **"Generate DTE"**

### Expected Result

**Warning Notification** (yellow):
```
⚠️ DTE Generated (Contingency)

DTE generated with folio 2.
Document stored locally and will be sent to SII when service recovers.
```

**Invoice Updated**:
- DTE Status: `Contingency`
- Folio: `2`
- Track ID: (empty - not sent to SII yet)
- is_contingency: `True`
- Chatter: "DTE generated in contingency mode. Will be sent when service recovers."

### Restore Service

```bash
# Start DTE Service
docker-compose start dte-service

# Wait for service to be healthy
docker-compose logs -f dte-service | grep "Application startup complete"
```

### Automatic Upload (Future Implementation)

**Note**: Automatic batch upload of contingency DTEs is scheduled for Week 2.

For now, you can manually re-send using legacy "Enviar a SII" button.

---

## Step 8: Test Query Status (3 min)

**Purpose**: Check DTE acceptance status from SII

### For Invoice with Track ID

1. Open invoice with `dte_status = 'sent'` and `dte_track_id` present

2. Click **"Query DTE Status"** button (header)

3. **Expected**:
   - Wizard or notification with status
   - Invoice updated with acceptance status
   - Chatter message: "DTE accepted/rejected by SII"

**Note**: In sandbox, this may return mock data. In production, queries real SII.

---

## Step 9: Test Error Handling (5 min)

**Purpose**: Verify user-friendly error messages

### Test 1: Missing Customer RUT

1. Create invoice without customer RUT
2. Post invoice
3. Click "Generate DTE"
4. **Expected**: Error dialog "Customer RUT is required"
5. Invoice status: unchanged (posted, not error)

### Test 2: No Available Folios

1. Modify CAF to `available_folios = 0` (via database or exhaust folios)
2. Post invoice
3. Click "Generate DTE"
4. **Expected**: Error dialog "CAF has no available folios. Please request new CAF from SII"

### Test 3: Expired Certificate

1. Modify certificate to `date_end = yesterday` (via database)
2. Post invoice
3. Click "Generate DTE"
4. **Expected**: Error dialog "Certificate has expired"

### Test 4: Invalid Data (DTE Service Validation)

1. Create invoice with negative amount
2. Post invoice
3. Click "Generate DTE"
4. **Expected**: Error dialog with specific validation message from DTE Service

---

## Step 10: Verify Security (3 min)

### Test Access Control

**As Account User**:
1. Login as user with `account.group_account_user` group
2. Navigate to Invoices → Can read invoices ✅
3. Open invoice → Can open "Generate DTE" wizard ✅
4. Navigate to Certificates → Can read certificates ✅
5. Try to delete certificate → **Should FAIL** ❌

**As Account Manager**:
1. Login as user with `account.group_account_manager` group
2. All above actions ✅
3. Delete test certificate → **Should SUCCEED** ✅

---

## Troubleshooting

### Issue: "DTE Service unavailable"

**Solution**:
```bash
# Check service running
docker-compose ps dte-service

# Check logs
docker-compose logs dte-service | tail -50

# Restart service
docker-compose restart dte-service

# Verify health
curl http://localhost:8001/health
```

### Issue: "Certificate validation failed"

**Solution**:
- Verify password is correct
- Verify certificate is `.p12` format (PKCS#12)
- Verify certificate is not expired
- Check DTE Service logs for details

### Issue: "CAF file invalid"

**Solution**:
- Verify CAF XML is from SII (not corrupted)
- Verify CAF is for correct DTE type (33, 34, 52, 56, 61)
- Verify CAF is not expired
- Check DTE Service logs for validation errors

### Issue: Wizard doesn't open

**Solution**:
```bash
# Check Odoo logs
docker-compose logs odoo | grep ERROR

# Verify module loaded
docker-compose exec odoo odoo shell -c /etc/odoo/odoo.conf -d odoo
>>> self.env['dte.generate.wizard']
# Should not raise error

# Verify views registered
>>> self.env['ir.ui.view'].search([('name', 'like', 'dte.generate.wizard')])
# Should return records
```

### Issue: Smart buttons don't appear

**Solution**:
- Verify `dte_xml` field has content
- Hard refresh browser (Ctrl+Shift+R)
- Clear Odoo assets cache: Settings → Technical → Assets → Clear
- Check browser console for JavaScript errors

---

## Next Steps After Testing

### If All Tests Pass ✅:

1. **Proceed to Staging Certification**:
   - Upload real certificates (Class 2/3 from SII)
   - Request real CAF files from Maullin
   - Generate 7 test DTEs (SII certification requirement)
   - Submit to SII for certification

2. **Implement Remaining Features** (Weeks 2-4):
   - PDF generation
   - Email DTE to customer
   - Automatic status polling (cron)
   - DTE Reception UI (Gap #1)
   - Contingency mode UI
   - Reports (Consumo Folios, Libros)

### If Tests Fail ❌:

1. **Document Errors**:
   - Screenshot error messages
   - Copy logs (Odoo, DTE Service, AI Service)
   - Note steps to reproduce

2. **Report Issues**:
   - Open GitHub issue with details
   - Tag: `integration`, `testing`, `bug`
   - Include: error logs, screenshots, steps to reproduce

3. **Investigate**:
   - Check ODOO_MODULE_INTEGRATION_SUMMARY.md for architecture
   - Review dte_service_integration.py for error handling logic
   - Check dte_generate_wizard.py for validation logic

---

## Performance Benchmarks

**Expected Metrics** (in development environment):

- Wizard load time: < 1 second
- DTE generation (sandbox): < 5 seconds
- Health check: < 1 second
- XML download: < 500ms

**If Slower**:
- Check DTE Service CPU/memory
- Check network latency (Odoo ↔ DTE Service)
- Enable profiling: `docker-compose logs dte-service | grep "took"`

---

## Success Criteria Checklist

- [ ] Module installs without errors
- [ ] Wizard opens correctly
- [ ] Service health displays correctly
- [ ] Certificate/CAF auto-selection works
- [ ] DTE generation succeeds (sandbox)
- [ ] Success notification appears
- [ ] Invoice fields updated correctly
- [ ] XML stored and downloadable
- [ ] QR code displayed
- [ ] Chatter message posted
- [ ] Contingency mode works (service down)
- [ ] Query status works (if track_id present)
- [ ] Error handling shows clear messages
- [ ] Security access control works
- [ ] No console errors (browser)
- [ ] No Python exceptions (Odoo logs)

---

## Conclusion

If all tests pass, the **Odoo + DTE Service integration is production-ready** for:
- ✅ Development testing
- ✅ Staging certification (Maullin)
- ⏳ Production deployment (after SII certification)

**Next Milestone**: SII Sandbox Certification (Week 1, Plan Opción C)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-22
**Status**: Ready for testing
