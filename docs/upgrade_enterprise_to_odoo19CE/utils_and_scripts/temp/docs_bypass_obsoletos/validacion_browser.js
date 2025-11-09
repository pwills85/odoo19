#!/usr/bin/env node
/**
 * Script de Validación Browser - Odoo 12 Enterprise Bypass
 * Usa Playwright para verificar el bypass en el navegador
 */

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Colores para consola
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function printSuccess(msg) {
  console.log(`${colors.green}✅ ${msg}${colors.reset}`);
}

function printError(msg) {
  console.log(`${colors.red}❌ ${msg}${colors.reset}`);
}

function printWarning(msg) {
  console.log(`${colors.yellow}⚠️  ${msg}${colors.reset}`);
}

function printInfo(msg) {
  console.log(`${colors.blue}ℹ️  ${msg}${colors.reset}`);
}

function printHeader(title) {
  console.log('\n' + '='.repeat(80));
  console.log(`${colors.blue}${title.padStart(40 + title.length/2).padEnd(80)}${colors.reset}`);
  console.log('='.repeat(80) + '\n');
}

async function validateOdooBypass() {
  const results = {
    pageLoad: false,
    noBlockingModal: false,
    bypassMessagesFound: false,
    loginAvailable: false,
    noExpirationWarning: false
  };

  let browser = null;
  let context = null;
  let page = null;

  try {
    printHeader('🌐 VALIDACIÓN BROWSER - ODOO 12 BYPASS');
    
    // 1. Lanzar navegador
    printInfo('Iniciando navegador Chrome...');
    browser = await chromium.launch({
      headless: false,  // Modo visual para ver qué pasa
      args: ['--ignore-certificate-errors']
    });
    
    context = await browser.newContext({
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true,
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    });
    
    page = await context.newPage();
    
    // Capturar mensajes de consola
    const consoleMessages = [];
    page.on('console', msg => {
      consoleMessages.push({
        type: msg.type(),
        text: msg.text()
      });
    });
    
    printSuccess('Navegador iniciado correctamente');
    
    // 2. Navegar a Odoo
    printHeader('📍 TEST 1: Carga de Página');
    printInfo('Navegando a https://odoo.gestionriego.cl...');
    
    const startTime = Date.now();
    try {
      await page.goto('https://odoo.gestionriego.cl', {
        waitUntil: 'networkidle',
        timeout: 60000
      });
      const loadTime = Date.now() - startTime;
      printSuccess(`Página cargada en ${loadTime}ms`);
      results.pageLoad = true;
    } catch (error) {
      printError(`Error cargando página: ${error.message}`);
      throw error;
    }
    
    // Esperar un momento para que se ejecuten los scripts
    await page.waitForTimeout(3000);
    
    // 3. Verificar que NO hay modal de bloqueo
    printHeader('🚫 TEST 2: Ausencia de Modal de Bloqueo');
    
    const blockingSelectors = [
      '.o_database_expiration_panel',
      '.oe_database_expiration_panel',
      '[data-qa="database_expiration_panel"]',
      '.modal-dialog:has-text("expiration")',
      '.modal-dialog:has-text("expired")',
      '[role="dialog"]:has-text("expiration")'
    ];
    
    let blockingModalFound = false;
    for (const selector of blockingSelectors) {
      const element = await page.$(selector);
      if (element) {
        const isVisible = await element.isVisible();
        if (isVisible) {
          printError(`Modal de bloqueo encontrado: ${selector}`);
          blockingModalFound = true;
          break;
        }
      }
    }
    
    if (!blockingModalFound) {
      printSuccess('No se encontró modal de bloqueo de expiración');
      results.noBlockingModal = true;
    }
    
    // 4. Verificar mensajes de bypass en consola
    printHeader('💬 TEST 3: Mensajes de Bypass en Consola');
    
    const bypassMessages = consoleMessages.filter(msg => 
      msg.text.includes('[BYPASS]') || 
      msg.text.includes('Enterprise expiration check disabled') ||
      msg.text.includes('Enterprise show panel disabled')
    );
    
    if (bypassMessages.length > 0) {
      printSuccess(`Se encontraron ${bypassMessages.length} mensajes de bypass:`);
      bypassMessages.forEach(msg => {
        console.log(`   📝 [${msg.type}] ${msg.text}`);
      });
      results.bypassMessagesFound = true;
    } else {
      printWarning('No se encontraron mensajes [BYPASS] en la consola');
      printInfo('Esto puede ser normal si los scripts aún no se ejecutaron');
    }
    
    // 5. Verificar que el login esté disponible
    printHeader('🔐 TEST 4: Disponibilidad de Login');
    
    const loginSelectors = [
      'input[name="login"]',
      'input[type="text"][placeholder*="mail"]',
      '.oe_login_form input[type="text"]',
      'form.oe_login_form'
    ];
    
    let loginFormFound = false;
    for (const selector of loginSelectors) {
      const element = await page.$(selector);
      if (element) {
        const isVisible = await element.isVisible();
        if (isVisible) {
          printSuccess(`Formulario de login encontrado y visible: ${selector}`);
          loginFormFound = true;
          results.loginAvailable = true;
          break;
        }
      }
    }
    
    if (!loginFormFound) {
      printWarning('No se pudo localizar el formulario de login');
      printInfo('Esto puede indicar que ya hay una sesión activa');
    }
    
    // 6. Verificar ausencia de warnings de expiración
    printHeader('⚠️  TEST 5: Ausencia de Warnings de Expiración');
    
    const expirationWarnings = [
      '.alert:has-text("expiration")',
      '.alert:has-text("expired")',
      '.notification:has-text("expiration")',
      '.o_notification:has-text("expiration")',
      '[role="alert"]:has-text("expiration")'
    ];
    
    let warningFound = false;
    for (const selector of expirationWarnings) {
      const element = await page.$(selector);
      if (element) {
        const isVisible = await element.isVisible();
        if (isVisible) {
          printError(`Warning de expiración encontrado: ${selector}`);
          warningFound = true;
          break;
        }
      }
    }
    
    if (!warningFound) {
      printSuccess('No se encontraron warnings de expiración');
      results.noExpirationWarning = true;
    }
    
    // 7. Tomar screenshot
    printHeader('📸 Captura de Pantalla');
    
    const screenshotPath = path.join(
      '/Users/pedro/Documents/oficina_server1/produccion/modulos_odoo18/prod_odoo-12',
      `screenshot_validacion_${Date.now()}.png`
    );
    
    await page.screenshot({ 
      path: screenshotPath,
      fullPage: true 
    });
    printSuccess(`Screenshot guardado: ${screenshotPath}`);
    
    // 8. Extraer información de la página
    printHeader('📄 Información de la Página');
    
    const pageTitle = await page.title();
    printInfo(`Título: ${pageTitle}`);
    
    const pageUrl = page.url();
    printInfo(`URL: ${pageUrl}`);
    
    // Buscar elementos relacionados con Odoo
    const odooVersion = await page.$eval('meta[name="generator"]', el => el.content)
      .catch(() => 'No detectada');
    printInfo(`Versión Odoo: ${odooVersion}`);
    
  } catch (error) {
    printError(`Error durante la validación: ${error.message}`);
    console.error(error);
  } finally {
    // Cerrar navegador
    if (page) await page.close();
    if (context) await context.close();
    if (browser) {
      printInfo('Cerrando navegador en 5 segundos...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      await browser.close();
    }
  }
  
  return results;
}

async function generateReport(results) {
  printHeader('📊 RESUMEN DE VALIDACIÓN BROWSER');
  
  const tests = [
    { name: 'Carga de página', passed: results.pageLoad },
    { name: 'Sin modal de bloqueo', passed: results.noBlockingModal },
    { name: 'Mensajes de bypass', passed: results.bypassMessagesFound },
    { name: 'Login disponible', passed: results.loginAvailable },
    { name: 'Sin warnings de expiración', passed: results.noExpirationWarning }
  ];
  
  let passed = 0;
  let failed = 0;
  
  tests.forEach(test => {
    if (test.passed) {
      printSuccess(test.name);
      passed++;
    } else {
      printError(test.name);
      failed++;
    }
  });
  
  const successRate = (passed / tests.length * 100).toFixed(1);
  
  console.log('\n' + '='.repeat(80));
  console.log(`Tests Pasados: ${colors.green}${passed}/${tests.length}${colors.reset}`);
  console.log(`Tasa de Éxito: ${successRate >= 80 ? colors.green : colors.red}${successRate}%${colors.reset}`);
  console.log('='.repeat(80));
  
  if (successRate >= 80) {
    printHeader('✅ VALIDACIÓN EXITOSA');
    printSuccess('El bypass está funcionando correctamente en el navegador');
    console.log('\n📋 Próximos pasos:');
    console.log('  1. Hacer login manualmente en https://odoo.gestionriego.cl');
    console.log('  2. Verificar navegación por módulos');
    console.log('  3. Probar operaciones CRUD básicas');
  } else {
    printHeader('⚠️  VALIDACIÓN CON PROBLEMAS');
    printWarning('Algunos tests no pasaron. Revisar la configuración.');
  }
  
  return successRate >= 80;
}

async function main() {
  console.log(`
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║           🧪 VALIDACIÓN BROWSER - ODOO 12 ENTERPRISE BYPASS                ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
  `);
  
  const results = await validateOdooBypass();
  const success = await generateReport(results);
  
  process.exit(success ? 0 : 1);
}

// Verificar que playwright esté instalado
try {
  require.resolve('playwright');
  main();
} catch (error) {
  printError('Playwright no está instalado');
  printInfo('Instalando Playwright...');
  const { execSync } = require('child_process');
  try {
    execSync('npm install -g playwright', { stdio: 'inherit' });
    execSync('npx playwright install chromium', { stdio: 'inherit' });
    printSuccess('Playwright instalado. Ejecutando validación...');
    main();
  } catch (installError) {
    printError('Error instalando Playwright');
    console.error(installError);
    process.exit(1);
  }
}
