#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generador de Módulo: web_ce_enterprise
Porta características UI/UX de Odoo Enterprise a Community Edition 19.0
"""

import os
import sys
from pathlib import Path


def create_directory_structure(base_path):
    """Crea la estructura de directorios del módulo"""
    
    directories = [
        '',
        'models',
        'views',
        'data',
        'security',
        'static',
        'static/description',
        'static/src',
        'static/src/js',
        'static/src/js/core',
        'static/src/js/home_menu',
        'static/src/js/mobile',
        'static/src/js/views',
        'static/src/js/widgets',
        'static/src/scss',
        'static/src/scss/components',
        'static/src/scss/layout',
        'static/src/scss/views',
        'static/src/scss/mobile',
        'static/src/xml',
        'static/src/fonts',
        'static/src/fonts/Roboto',
        'static/src/img',
        'static/src/img/mobile-icons',
        'tests',
        'tests/static',
        'tests/static/tests',
    ]
    
    for directory in directories:
        path = Path(base_path) / directory
        path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Creado: {path}")
    
    return True


def create_manifest(base_path):
    """Crea el archivo __manifest__.py"""
    
    content = '''# -*- coding: utf-8 -*-
{
    'name': 'Web Community Enterprise',
    'version': '19.0.1.0.0',
    'category': 'Hidden',
    'summary': 'Enterprise UI/UX for Odoo Community Edition',
    'description': """
Enterprise Design and User Experience for Community Edition
============================================================

This module brings the professional look and feel of Odoo Enterprise 
to Community Edition, including:

* Modern Home Menu with app icons and search
* Responsive mobile menu and navigation
* Enhanced control panel with adaptive breadcrumbs
* Enterprise typography (Roboto font family)
* Professional color scheme and design system
* Touch-optimized interface for mobile devices
* Improved form, list, and kanban views
* Smooth animations and transitions

Features
--------
- **Home Menu**: Beautiful app grid with search functionality
- **Mobile First**: Touch-optimized navigation and controls
- **Responsive**: Adapts to any screen size seamlessly
- **Modern Design**: Clean, professional enterprise look
- **Performance**: Optimized assets and lazy loading

This is a clean-room implementation inspired by Odoo Enterprise's design,
fully compatible with LGPL-3 license.
    """,
    'author': 'Community',
    'website': 'https://github.com/yourusername/web_ce_enterprise',
    'license': 'LGPL-3',
    'depends': [
        'web',
    ],
    'data': [
        'views/webclient_templates.xml',
    ],
    'assets': {
        'web._assets_primary_variables': [
            'web_ce_enterprise/static/src/scss/primary_variables.scss',
        ],
        'web._assets_secondary_variables': [
            'web_ce_enterprise/static/src/scss/secondary_variables.scss',
        ],
        'web.assets_backend': [
            # Fonts
            'web_ce_enterprise/static/src/scss/fonts.scss',
            
            # Variables
            'web_ce_enterprise/static/src/scss/_variables.scss',
            'web_ce_enterprise/static/src/scss/_mixins.scss',
            
            # Components
            'web_ce_enterprise/static/src/scss/components/_buttons.scss',
            'web_ce_enterprise/static/src/scss/components/_inputs.scss',
            'web_ce_enterprise/static/src/scss/components/_badges.scss',
            'web_ce_enterprise/static/src/scss/components/_alerts.scss',
            
            # Layout
            'web_ce_enterprise/static/src/scss/layout/_webclient.scss',
            'web_ce_enterprise/static/src/scss/layout/_control_panel.scss',
            'web_ce_enterprise/static/src/scss/layout/_home_menu.scss',
            
            # Views
            'web_ce_enterprise/static/src/scss/views/_form.scss',
            'web_ce_enterprise/static/src/scss/views/_list.scss',
            'web_ce_enterprise/static/src/scss/views/_kanban.scss',
            
            # Mobile
            'web_ce_enterprise/static/src/scss/mobile/_menu_mobile.scss',
            'web_ce_enterprise/static/src/scss/mobile/_touch_device.scss',
            
            # JavaScript - Core
            'web_ce_enterprise/static/src/js/core/web_client.js',
            'web_ce_enterprise/static/src/js/core/menu.js',
            
            # JavaScript - Home Menu
            'web_ce_enterprise/static/src/js/home_menu/home_menu.js',
            'web_ce_enterprise/static/src/js/home_menu/apps.js',
            
            # JavaScript - Mobile
            'web_ce_enterprise/static/src/js/mobile/control_panel.js',
            'web_ce_enterprise/static/src/js/mobile/menu_mobile.js',
            
            # JavaScript - Views
            'web_ce_enterprise/static/src/js/views/form_renderer.js',
            'web_ce_enterprise/static/src/js/views/form_view.js',
            
            # JavaScript - Widgets
            'web_ce_enterprise/static/src/js/widgets/user_menu.js',
            
            # Templates
            ('include', 'web_ce_enterprise.assets_qweb'),
        ],
        'web_ce_enterprise.assets_qweb': [
            'web_ce_enterprise/static/src/xml/*.xml',
        ],
    },
    'images': [
        'static/description/banner.png',
        'static/description/icon.png',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
}
'''
    
    manifest_path = Path(base_path) / '__manifest__.py'
    with open(manifest_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Creado: {manifest_path}")
    return True


def create_init_files(base_path):
    """Crea los archivos __init__.py"""
    
    init_files = [
        '',
        'models',
        'tests',
    ]
    
    for directory in init_files:
        init_path = Path(base_path) / directory / '__init__.py'
        
        if directory == '':
            content = "# -*- coding: utf-8 -*-\nfrom . import models\n"
        elif directory == 'models':
            content = "# -*- coding: utf-8 -*-\n# from . import ir_http\n"
        else:
            content = "# -*- coding: utf-8 -*-\n"
        
        with open(init_path, 'w') as f:
            f.write(content)
        
        print(f"✓ Creado: {init_path}")
    
    return True


def create_readme(base_path):
    """Crea el archivo README.md"""
    
    content = '''# Web Community Enterprise

[![License: LGPL-3](https://img.shields.io/badge/license-LGPL--3-blue)](https://www.gnu.org/licenses/lgpl-3.0)
[![Odoo Version](https://img.shields.io/badge/Odoo-19.0-brightgreen)](https://www.odoo.com)

Enterprise UI/UX for Odoo Community Edition

## Features

This module brings the professional look and feel of Odoo Enterprise to Community Edition:

### 🎨 Design System
- **Enterprise Color Palette**: Professional color scheme
- **Roboto Typography**: Modern, clean font family
- **Material Design**: Buttons, inputs, and components
- **Smooth Animations**: Transitions and hover effects

### 🏠 Home Menu
- **App Grid**: Beautiful icon-based app launcher
- **Smart Search**: Real-time search for apps and menus
- **Keyboard Navigation**: Arrow keys, Enter, Escape
- **Customizable Background**: Support for custom images

### 📱 Mobile First
- **Responsive Design**: Works on any screen size
- **Touch Optimized**: Large touch targets, gestures
- **Mobile Menu**: Hamburger navigation
- **Adaptive Controls**: Context-aware UI elements

### 📊 Enhanced Views
- **Form Views**: Improved layout, chatter positioning
- **List Views**: Better headers, hover effects
- **Kanban Views**: Smooth drag & drop
- **Control Panel**: Adaptive breadcrumbs and search

## Installation

### Using Git

```bash
cd /path/to/odoo/addons
git clone https://github.com/yourusername/web_ce_enterprise.git
```

### Manual Installation

1. Download the module
2. Extract to your Odoo addons directory
3. Restart Odoo server
4. Update Apps List
5. Install "Web Community Enterprise"

## Requirements

- Odoo 19.0 Community Edition
- Modern web browser (Chrome, Firefox, Safari, Edge)
- Internet connection (for downloading Roboto fonts)

## Configuration

No configuration needed! The module works out of the box.

### Optional: Custom Home Menu Background

Add your custom background image:
```bash
cp your_image.jpg static/src/img/home-menu-bg-custom.jpg
```

Then add to your `res.company` settings.

## Usage

After installation, you'll immediately see:

1. **Home Menu**: Click the Odoo logo to see the new app launcher
2. **Mobile Menu**: Resize your browser to mobile size to see responsive design
3. **Enhanced Controls**: Navigate through forms and lists with improved UI

## Development

### Project Structure

```
web_ce_enterprise/
├── models/              # Python models (if needed)
├── views/               # XML views and templates
├── static/
│   └── src/
│       ├── js/          # JavaScript (OWL components)
│       ├── scss/        # Stylesheets
│       ├── xml/         # QWeb templates
│       ├── fonts/       # Roboto fonts
│       └── img/         # Images and icons
└── tests/               # Unit and integration tests
```

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards

- Follow [Odoo Development Guidelines](https://www.odoo.com/documentation/19.0/developer/reference/backend/orm.html)
- Use [OWL Framework](https://github.com/odoo/owl) for JavaScript components
- Follow [BEM methodology](http://getbem.com/) for CSS classes
- Write tests for new features

## Testing

Run tests:
```bash
odoo-bin -c odoo.conf -d test_db --test-tags web_ce_enterprise --stop-after-init
```

## License

This module is licensed under LGPL-3.

## Credits

### Contributors

- Your Name <your.email@example.com>

### Inspiration

Design inspired by Odoo Enterprise, implemented independently for Community Edition.

### Maintainer

This module is maintained by the community.

## Support

For questions, issues, or contributions:
- GitHub Issues: https://github.com/yourusername/web_ce_enterprise/issues
- Odoo Community: https://www.odoo.com/forum
- Email: your.email@example.com

## Changelog

### Version 19.0.1.0.0 (2025-11-03)

- Initial release
- Home menu with app grid
- Responsive mobile menu
- Enterprise color scheme
- Roboto typography
- Enhanced form/list/kanban views
'''
    
    readme_path = Path(base_path) / 'README.md'
    with open(readme_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Creado: {readme_path}")
    return True


def create_base_scss(base_path):
    """Crea los archivos SCSS base"""
    
    # _variables.scss
    variables_content = '''// Web CE Enterprise - Variables
// Primary color scheme based on Odoo Enterprise

// Brand Colors
$o-brand-odoo: #714B67 !default;
$o-brand-primary: #714B67 !default;
$o-brand-secondary: #8f8f8f !default;
$o-brand-lightsecondary: #f5f5f5 !default;

// Text Colors
$o-main-text-color: #666666 !default;

// Layout
$o-font-size-base-touch: 15px !default;
$o-statbutton-height: 44px !default;
$o-home-menu-container-size: 850px !default;

// Animations
$o-transition-time: 0.3s !default;
'''
    
    variables_path = Path(base_path) / 'static/src/scss/_variables.scss'
    with open(variables_path, 'w') as f:
        f.write(variables_content)
    
    # _mixins.scss
    mixins_content = '''// Web CE Enterprise - Mixins

@mixin o-text-overflow($display: inline-block) {
    @if $display == block {
        display: block;
    } @else {
        display: inline-block;
    }
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

@mixin o-transition($property: all, $duration: $o-transition-time, $timing: ease) {
    transition: $property $duration $timing;
}

@mixin o-hover-effect {
    @include o-transition(all, 0.2s, ease);
    
    &:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 15px -10px rgba(0, 0, 0, 0.3);
    }
}
'''
    
    mixins_path = Path(base_path) / 'static/src/scss/_mixins.scss'
    with open(mixins_path, 'w') as f:
        f.write(mixins_content)
    
    print(f"✓ Creados: archivos SCSS base")
    return True


def create_license(base_path):
    """Crea el archivo LICENSE"""
    
    content = '''GNU LESSER GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2025 Community Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''
    
    license_path = Path(base_path) / 'LICENSE'
    with open(license_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Creado: {license_path}")
    return True


def main():
    """Función principal"""
    
    print("""
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   Generador de Módulo: web_ce_enterprise             ║
║   Odoo 19.0 Community Edition                        ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Obtener path de destino
    if len(sys.argv) > 1:
        base_path = sys.argv[1]
    else:
        base_path = input("Ruta de destino (default: ./web_ce_enterprise): ").strip()
        if not base_path:
            base_path = "./web_ce_enterprise"
    
    base_path = Path(base_path).resolve()
    
    print(f"\n📁 Creando módulo en: {base_path}\n")
    
    try:
        # Crear estructura
        create_directory_structure(base_path)
        print()
        
        # Crear archivos base
        create_manifest(base_path)
        create_init_files(base_path)
        create_readme(base_path)
        create_base_scss(base_path)
        create_license(base_path)
        
        print(f"""
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║   ✅ Módulo creado exitosamente                      ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

📦 Estructura del módulo:
   {base_path}/

🚀 Próximos pasos:

1. Descargar fuentes Roboto:
   wget https://fonts.google.com/download?family=Roboto
   Extraer en: static/src/fonts/Roboto/

2. Crear componentes JavaScript (OWL):
   - static/src/js/home_menu/home_menu.js
   - static/src/xml/home_menu.xml

3. Implementar estilos SCSS:
   - static/src/scss/layout/_home_menu.scss
   - static/src/scss/components/_buttons.scss

4. Agregar al addons_path de Odoo:
   --addons-path=/path/to/addons,{base_path}

5. Actualizar Apps List e instalar el módulo

📚 Documentación:
   - README.md: Guía completa
   - ANALISIS_ENTERPRISE_TO_CE.md: Análisis técnico

🎯 Happy coding!
        """)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
