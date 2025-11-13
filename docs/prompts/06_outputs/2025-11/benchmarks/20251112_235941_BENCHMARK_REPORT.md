# 🧪 CLI Benchmark Report - Inteligencia, Rapidez, Locuacidad

**Fecha:** 2025-11-13 00:25:57
**Sesión:** 20251112_235941

---

## 📊 Resumen Ejecutivo

Este reporte compara el rendimiento de diferentes CLI tools y modelos.

---

## ⚡ Test 1: Rapidez (Latencia Simple)

| CLI | Modelo | Duración (s) | Palabras |
|-----|--------|--------------|----------|
| gemini | gemini-2.5-flash-lite | 139.50 |       64 |
| gemini | gemini-2.5-flash | 31.71 |       69 |
| gemini | gemini-2.5-pro | 28.53 |       99 |
| copilot | gpt-4 | 12.84 |       96 |
| codex | gpt-4-turbo | 9.69 |      235 |

---

## 🧠 Test 2: Inteligencia (Compliance Check)

| CLI | Modelo | Duración (s) | Referencias | Deprecaciones |
|-----|--------|--------------|-------------|---------------|
| gemini | gemini-2.5-flash-lite | 77.01 |        0 |  |
| 0 | 1 | 0.00 |  |  |
| gemini | gemini-2.5-flash | 44.17 |        0 |  |
| 0 | 6 | 0.00 |  |  |
| gemini | gemini-2.5-pro | 131.61 |        0 |  |
| 0 | 1 | 0.00 |  |  |
| copilot | gpt-4 | 90.84 |        1 | 5 |
| codex | gpt-4-turbo | 0.06 |        0 |  |
| 0 | 0 | 0.00 |  |  |
| 0 |  | 0.00 |  |  |

---

## 💬 Test 3: Locuacidad (Análisis Detallado)

| CLI | Modelo | Duración (s) | Palabras | Secciones | Referencias | Bloques Código | Densidad Útil (%) |
|-----|--------|--------------|----------|-----------|-------------|----------------|-------------------|
| gemini | gemini-2.5-flash-lite | 362.60 |    33369 | 0 |  |  | 0.00 |
| 0 |        0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 |  | 0.00 |  |  |  |  | 0.00 |
| gemini | gemini-2.5-flash | 84.58 |     1930 | 0 |  |  | 0.00 |
| 0 |        0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 |  | 0.00 |  |  |  |  | 0.00 |
| gemini | gemini-2.5-pro | 126.55 |     1137 | 6 |        5 | 10 | 0.43 |
| copilot | gpt-4 | 418.16 |     2122 | 73 |       36 | 58 | 1.69 |
| codex | gpt-4-turbo | 0.04 |       22 | 0 |  |  | 0.00 |
| 0 |        0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 | 0 | 0.00 |  |  |  |  | 0.00 |
| 0 |  | 0.00 |  |  |  |  | 0.00 |

---

## 📁 Archivos Generados

Todos los outputs están en: docs/prompts/06_outputs/2025-11/benchmarks

**Generado:** Thu Nov 13 00:25:57 -03 2025
