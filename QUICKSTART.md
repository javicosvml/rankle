# Rankle v1.1 - Guía Rápida

## 🚀 Inicio Rápido

### 1. Instalación (primera vez)
```bash
cd /Users/javiercoscolla/hack/hack-toolbox
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Uso Básico
```bash
# Activar entorno virtual
source venv/bin/activate

# Escanear un dominio
python rankle.py www.contraelcancer.es

# Guardar como JSON
python rankle.py www.contraelcancer.es --json

# Guardar ambos formatos
python rankle.py www.contraelcancer.es --output both
```

## ✅ Verificación de Mejoras

### Test rápido - www.contraelcancer.es
```bash
source venv/bin/activate
python rankle.py www.contraelcancer.es 2>&1 | grep -E "CMS:|CDN:|WAF:"
```

**Resultado esperado:**
```
CMS:               Drupal
CDN:               TransparentEdge
WAF:               TransparentEdge WAF
```

## 📋 Qué se detecta ahora

### CMS (16 sistemas)
- ✅ **Drupal** con 15+ patrones
- WordPress, Joomla, Magento, Shopify
- TYPO3, Concrete5, ModX, etc.

### CDN (20+ proveedores)
- ✅ **TransparentEdge**
- Cloudflare, Akamai, Fastly
- Azure, Google Cloud, MaxCDN, etc.

### WAF (15+ soluciones)
- ✅ **TransparentEdge WAF**
- Cloudflare, Imperva, Sucuri
- PerimeterX, DataDome, ModSecurity, etc.

### Tecnologías
- Frameworks JS: React, Vue, Angular
- Librerías: jQuery, Bootstrap, D3.js
- Analytics: Google Analytics, GTM, etc.

## 📖 Documentación Completa

- **README.md** - Documentación principal (inglés)
- **MEJORAS.md** - Guía detallada de mejoras (español)
- **CHANGELOG.md** - Historial de cambios
- **SUMMARY.md** - Resumen ejecutivo

## 🎯 Ejemplos de Uso

### Escaneo simple
```bash
python rankle.py example.com
```

### Con exportación JSON (para herramientas)
```bash
python rankle.py example.com --json
cat example_com_rankle.json | jq -r '.technologies_web.cms'
```

### Pipeline con otras herramientas
```bash
# Extraer subdominios
python rankle.py example.com --json
cat example_com_rankle.json | jq -r '.subdomains[]' > subdomains.txt

# Alimentar a nuclei
nuclei -l subdomains.txt -t nuclei-templates/
```

## 🔍 Casos de Uso

### Reconocimiento inicial
```bash
python rankle.py target.com --output both
```

### Bug Bounty
```bash
# Enumerar subdominios
python rankle.py target.com --json
jq -r '.subdomains[]' target_com_rankle.json > subs.txt

# Detectar tecnologías
jq -r '.technologies_web' target_com_rankle.json
```

### Auditoría de seguridad
```bash
# Verificar headers de seguridad
python rankle.py target.com --json
jq '.security_headers' target_com_rankle.json

# Verificar CDN/WAF
jq -r '"\(.cdn) / \(.waf)"' target_com_rankle.json
```

## 💡 Tips

1. **Activar venv siempre**: `source venv/bin/activate`
2. **JSON para automation**: `--json` o `--output both`
3. **Texto para revisión manual**: más fácil de leer
4. **Respetar rate limits**: no hacer scan masivo
5. **Verificar /robots.txt**: respeta las reglas del sitio

## 🐛 Troubleshooting

### Error: Missing dependencies
```bash
pip install -r requirements.txt
```

### Error: Permission denied
```bash
chmod +x test_enhancements.sh
```

### Error: venv not found
```bash
python3 -m venv venv
source venv/bin/activate
```

## 🎉 ¡Listo!

Rankle v1.1 está configurado y listo para usar con:
- ✅ Detección mejorada de Drupal
- ✅ 20+ CDNs detectables
- ✅ 15+ WAFs detectables
- ✅ WHOIS robusto
- ✅ 15+ librerías JS

---
**Rankle: Master of Pranks knows all your secrets**
