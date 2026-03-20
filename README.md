# T-Pot Hive Checker

![Platform](https://img.shields.io/badge/platform-Kali%20Linux-blue)
![Shell](https://img.shields.io/badge/shell-bash-informational)
![Purpose](https://img.shields.io/badge/purpose-T--Pot%20validation-success)
![Status](https://img.shields.io/badge/status-lab%20use%20only-orange)

Script para comprobar una instalación **T-Pot estándar / hive** generando tráfico **benigno y controlado** contra los honeypots expuestos, con el objetivo de verificar que aparecen eventos en **Kibana / Discover**.

---

## TL;DR

- Pide la **IP objetivo** al comenzar.
- Clasifica la IP como:
  - **privada RFC1918**
  - **especial/reservada**
  - **pública real**
- Si la IP no es privada, obliga a escribir `si` para continuar.
- Ofrece dos modos:
  - **Básico**: validación rápida de honeypots comunes.
  - **Completo**: intenta generar eventos en todos los honeypots activos de la edición estándar / hive.
- Mientras se ejecuta, muestra:
  - qué está haciendo,
  - para qué lo hace,
  - y el **comando exacto** que está lanzando.
- Guarda toda la salida en un **log local**.
- Está pensado para **Kali Linux 2025.4**.

---

## Tabla de contenidos

- [Qué es este proyecto](#qué-es-este-proyecto)
- [Sistema operativo objetivo](#sistema-operativo-objetivo)
- [Qué hace el script](#qué-hace-el-script)
- [Qué no hace](#qué-no-hace)
- [Cobertura de honeypots](#cobertura-de-honeypots)
  - [Modo básico](#modo-básico)
  - [Modo completo](#modo-completo)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Flujo de ejecución](#flujo-de-ejecución)
- [Qué tipo de pruebas realiza](#qué-tipo-de-pruebas-realiza)
- [Archivo de log](#archivo-de-log)
- [Cómo comprobar los resultados en T-Pot](#cómo-comprobar-los-resultados-en-t-pot)
- [Limitaciones](#limitaciones)
- [Seguridad y uso responsable](#seguridad-y-uso-responsable)
- [Fuentes oficiales](#fuentes-oficiales)
- [Licencia](#licencia)
- [Mejoras futuras](#mejoras-futuras)

---

## Qué es este proyecto

Este repositorio contiene un script de apoyo para laboratorios con T-Pot. Su finalidad es **provocar eventos observables** en los honeypots de una instalación T-Pot sin usar payloads destructivos ni explotación de vulnerabilidades.

La idea es:

1. lanzar interacciones mínimas y benignas contra los servicios expuestos;
2. forzar que esos servicios registren actividad;
3. comprobar después en **Kibana / Discover** que T-Pot está ingiriendo y mostrando los logs correctamente.

---

## Sistema operativo objetivo

**Diseñado para:**

- **Kali Linux**
- **Versión objetivo:** **Kali Linux 2025.4**
- **Shell:** `bash`

Aunque está escrito pensando en Kali, en la práctica debería funcionar también en Debian o Ubuntu si se instalan las herramientas necesarias.

---

## Qué hace el script

El script:

- pide la IP objetivo;
- valida que sea una IPv4 correcta;
- determina si la IP es:
  - **privada RFC1918**
  - **especial/reservada**
  - **pública real**
- exige confirmación manual si la IP no es privada;
- enseña una tabla previa con los honeypots que se van a poner a prueba;
- permite seleccionar entre **modo básico** y **modo completo**;
- ejecuta pruebas benignas como:
  - escaneos con `nmap`,
  - peticiones HTTP/HTTPS con `curl`,
  - conexiones TCP simples con `nc`,
  - intentos de conexión SSH,
  - handshakes TLS con `openssl`,
  - y, si están disponibles, clientes específicos como `adb` o `redis-cli`;
- muestra en pantalla:
  - **qué está haciendo**,
  - **para qué lo está haciendo**,
  - **el comando exacto**;
- guarda todo en un archivo de log.

---

## Qué no hace

Este script **no** está pensado para:

- explotar vulnerabilidades;
- comprometer servicios;
- desplegar malware;
- modificar la instalación objetivo;
- realizar acciones destructivas;
- automatizar explotación ofensiva.

Su objetivo es **validación de registro y visibilidad**, no explotación.

---

## Cobertura de honeypots

La cobertura se basa en la **edición estándar / hive actual** de T-Pot.

### Modo básico

| Honeypot | Herramientas |
|---|---|
| Cowrie | `ssh`, `nc` |
| Dionaea | `nmap` |
| ElasticPot | `curl` |
| H0neytr4p | `curl` |
| Honeyaml | `curl` |
| Mailoney | `nc` |
| Snare / Tanner | `curl` |
| Wordpot | `curl` |

### Modo completo

| Honeypot | Herramientas |
|---|---|
| ADBHoney | `adb` o `nmap` |
| CiscoASA | `curl`, `nmap` |
| Conpot | `nmap` |
| Cowrie | `ssh`, `nc` |
| Dicompot | `nmap` |
| Dionaea | `nmap` |
| ElasticPot | `curl` |
| H0neytr4p | `curl` |
| Heralding | `nc`, `openssl` |
| Honeyaml | `curl` |
| Honeytrap | `nmap` |
| IPPHoney | `nmap`, `nc` |
| Mailoney | `nc` |
| Medpot | `nmap`, `nc` |
| Miniprint | `nc` |
| Redishoneypot | `redis-cli` o `nc` |
| SentryPeer | `nmap`, `nc` |
| Snare / Tanner | `curl` |
| Wordpot | `curl` |

---

## Requisitos

### Requeridos

- `bash`
- `nmap`
- `curl`
- `nc`
- `ssh`
- `openssl`

### Opcionales

- `adb`
- `redis-cli`
- `timeout`
- `telnet`

---

## Instalación

### Clonar el repositorio

```bash
git clone https://github.com/victordanielteleco/tpot-hive-checker.git
cd victordanielteleco
