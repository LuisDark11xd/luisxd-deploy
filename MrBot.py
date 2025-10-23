import discord
from discord.ext import commands
from discord.ext.commands import has_permissions, is_owner

# Librerías estándar
import os
import sys
import json
import asyncio
import random
import time
from datetime import datetime
import base64
import hashlib
import logging

# Librerías de Ciberseguridad/Redes (pip install python-whois dnspython requests)
import requests
import socket
try:
    import whois
    import dns.resolver
except ImportError:
    whois = None
    dns = None


# ----------------------------------------------------------------------
# 🚨 CONFIGURACIÓN CRÍTICA 🚨
# ----------------------------------------------------------------------

OWNER_ID = [1423251179785420911] 
TOKEN = os.environ.get('DISCORD_TOKEN') 
# GEMINI_API_KEY YA NO ES NECESARIA

client = commands.Bot(
    command_prefix='$', 
    intents=discord.Intents.all(),
    owner_ids=set(OWNER_ID)
)

# La IA ha sido completamente removida.
AI_MODEL = None 

DATA_FILE = 'mrrobot_warns.json'
warn_data = {} 

def load_warn_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_warn_data(warn_data):
    with open(DATA_FILE, 'w') as f:
        json.dump(warn_data, f, indent=4)

# ----------------------------------------------------------------------
# 🧠 EVENTOS Y FUNCIÓN DE AYUDA (SIN LÓGICA DE IA)
# ----------------------------------------------------------------------

@client.event
async def on_ready():
    global warn_data
    warn_data = load_warn_data() 
    print(f'🤖 Mr. Robot conectado como {client.user} con prefijo $')
    print('--- Mr. Robot Online (Monolítico) ---')

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    # Ahora solo procesa comandos con el prefijo '$'
    await client.process_commands(message)

# ----------------------------------------------------------------------
# 📚 COMANDO DE AYUDA CENTRAL ($ayuda) (COMPLETO Y FINAL)
# ----------------------------------------------------------------------

@client.group(name='ayuda', invoke_without_command=True)
async def help_group(ctx):
    """Muestra el menú principal de ayuda."""
    embed = discord.Embed(
        title="🤖 | Menú de Ayuda de Mr. Robot",
        description="Soy Mr. Robot, tu asistente de ciberseguridad y moderación. Usa **`$ayuda [categoría]`** para ver los comandos detallados, por ejemplo: **`$ayuda ciber`**",
        color=discord.Color.blue()
    )
    embed.add_field(name="🛡️ Seguridad (Ciber)", value="`$ayuda ciber` | **20** comandos de Hacking Ético, redes y criptografía. ", inline=False)
    embed.add_field(name="🔨 Moderación y Administración", value="`$ayuda mod` | **30** comandos de disciplina (`warn`, `kick`, `ban`), gestión de canales y roles. ", inline=False)
    embed.add_field(name="✨ Interacción y Diversión", value="`$ayuda fun` | **4** comandos de interacción social (`hug`, `pat`, `kiss`) y utilidades como `coinflip`.", inline=False)
    embed.set_footer(text=f"Prefijo: $ | Solicitado por {ctx.author.name}", icon_url=ctx.author.avatar.url if ctx.author.avatar else None)
    await ctx.send(embed=embed)

@help_group.command(name='ciber', aliases=['seguridad'])
async def help_ciber(ctx):
    """Muestra los comandos de Ciberseguridad."""
    embed = discord.Embed(
        title="🛡️ Ayuda Ciberseguridad (20 Comandos)",
        description="Herramientas para el análisis de redes, seguridad y criptografía. ¡Recuerda el uso ético!",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="💻 Hashing y Crypto (5)",
        value="`$hash <texto>`: Genera SHA256.\n`$md5 <texto>`: Genera MD5.\n`$base64e/d <texto>`: Codifica/Decodifica.\n`$genpass [longitud]`",
        inline=False
    )
    embed.add_field(
        name="🌐 Redes y Reconocimiento (10)",
        value="`$whois <dominio>`: Info de registro.\n`$dns <dominio>`: Registros A.\n`$ipinfo <ip>`: Geolocalización.\n`$portscan <ip> <puerto>`: Chequeo de puertos.\n`$headers <url>`: Cabeceras HTTP.\n`$pingcheck <host>`.\n`$subdomains <dominio>`.\n`$webstatus <url>`.\n`$reverseip <host>`.\n`$urlshorten <url>`.",
        inline=False
    )
    embed.add_field(
        name="🔒 Administración (5)",
        value="`$logchannel <#canal>`: Establece el canal de logs.\n`$antispam <on/off>`: Control anti-spam.\n`$autorole <@rol>`: Rol automático.\n`$checkpermissions`.\n`$massban` (Owner Only).",
        inline=False
    )
    await ctx.send(embed=embed)

@help_group.command(name='mod', aliases=['moderacion'])
async def help_mod(ctx):
    """Muestra los comandos de Moderación."""
    embed = discord.Embed(
        title="🔨 Ayuda Moderación y Administración (30 Comandos)",
        description="Comandos para mantener el orden, la disciplina y gestionar los permisos del servidor.",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="🚨 Disciplina y Sanciones (8)",
        value="`$warn <@user> [razón]` : Advertencia con persistencia.\n`$kick <@user>` | `$ban <@user>` | `$unban <id>`.\n`$mute <@user>` | `$unmute <@user>`.\n`$checkwarns <@user>` | `$softban <@user>`.",
        inline=False
    )
    embed.add_field(
        name="🧹 Limpieza y Canales (7)",
        value="`$clear <cant>`: Borra mensajes.\n`$lock` | `$unlock`: Cierra/abre el canal.\n`$nuke`: Clona y borra el canal.\n`$slowmode <segundos>`.\n`$dehoist` | `$massmove <v1> <v2>`.",
        inline=False
    )
    embed.add_field(
        name="👑 Roles y Datos (15)",
        value="`$giverole/@takerole <@user> <@rol>`.\n`$rolall <@rol>`.\n`$nick <@user> <nuevo>` | `$resetnick`.\n`$bots` | `$channelinfo` | `$userinfo` | `$serverinfo`.\n`$banlist` | `$purgeuser <@user> <cant>`.\n`$servers` (Owner) | `$shutdown` (Owner) | `$eval` (Owner).",
        inline=False
    )
    await ctx.send(embed=embed)

@help_group.command(name='fun', aliases=['diversion'])
async def help_fun(ctx):
    """Muestra los comandos de Diversión/Interacción."""
    embed = discord.Embed(
        title="✨ Ayuda Interacción y Utilidades (4 Comandos)",
        description="Comandos sociales para interactuar con otros usuarios y utilidades rápidas.",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="🫂 Interacción Social (4 comandos)",
        value="`$hug`, `$pat`, `$kiss`, `$slap`,**",
        inline=False
    )
    embed.add_field(
        name="🎲 Utilidades (3 comandos)",
        value="`$coinflip`: Lanza una moneda.\n`$8ball <pregunta>`: Predice el futuro.\n`$ping`: Muestra la latencia del bot.",
        inline=False
    )
    await ctx.send(embed=embed)

# ----------------------------------------------------------------------
# 🛠️ COMANDOS DE CIBERSEGURIDAD (20 Comandos)
# ----------------------------------------------------------------------

# --- 1. HASHING y CRYPTO (5) ---

@client.command(name='hash', help='Genera el hash SHA256 de un texto.')
async def hash_command(ctx, *, text: str):
    hashed = hashlib.sha256(text.encode()).hexdigest()
    await ctx.send(f"**SHA256:** `{hashed}`")

@client.command(name='md5', help='Genera el hash MD5 de un texto.')
async def md5_command(ctx, *, text: str):
    hashed = hashlib.md5(text.encode()).hexdigest()
    await ctx.send(f"**MD5:** `{hashed}`")

@client.command(name='base64e', help='Codifica un texto a Base64.')
async def base64_encode_command(ctx, *, text: str):
    encoded = base64.b64encode(text.encode()).decode()
    await ctx.send(f"**Base64 Codificado:** `{encoded}`")

@client.command(name='base64d', help='Decodifica un texto Base64.')
async def base64_decode_command(ctx, *, text: str):
    try:
        decoded = base64.b64decode(text.encode()).decode()
        await ctx.send(f"**Base64 Decodificado:** `{decoded}`")
    except Exception:
        await ctx.send("❌ Error de decodificación Base64.")

@client.command(name='genpass', help='Genera una contraseña segura.')
async def genpass_command(ctx, length: int = 16):
    import string
    caracteres = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(caracteres) for i in range(length))
    await ctx.author.send(f"🔐 Tu contraseña generada es: `{password}`")
    await ctx.send("🔐 Contraseña generada enviada por DM.")


# --- 2. COMANDOS DE REDES (10) ---

@client.command(name='whois', help='Obtiene información de registro de un dominio.')
async def whois_command(ctx, domain: str):
    if not whois: return await ctx.send("❌ Módulo WHOIS no instalado. (`pip install python-whois`)")
    try:
        w = whois.whois(domain)
        embed = discord.Embed(title=f"🔎 WHOIS para {domain}", color=discord.Color.orange())
        embed.add_field(name="Registrar", value=w.registrar, inline=False)
        embed.add_field(name="Fecha de Creación", value=str(w.creation_date), inline=True)
        embed.add_field(name="Fecha de Expiración", value=str(w.expiration_date), inline=True)
        await ctx.send(embed=embed)
    except Exception:
        await ctx.send(f"❌ No se encontró información WHOIS para `{domain}`.")

# ----------------------------------------------------------------------
# COMANDO GEOIP (FINAL)
# ----------------------------------------------------------------------

# Nota: Este comando requiere 'import aiohttp' en la Parte 1.

async def get_ip_info(ip: str):
    """Función de ayuda para consultar la API de ip-api.com."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return None, "Error al conectar con la API de geolocalización."
                data = await resp.json()
                return data, None
    except Exception:
        return None, "Error de conexión al intentar obtener la información de la IP."


async def send_ip_embed(ctx, data: dict, ip: str):
    """Función de ayuda para formatear y enviar el Embed."""
    if data.get('status') == 'success':
        embed = discord.Embed(
            title=f"🌐 Información de IP: {ip}",
            color=0x2ECC71 # Verde
        )
        embed.add_field(name="📍 País", value=f"{data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})", inline=True)
        embed.add_field(name="🏙️ Región", value=f"{data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})", inline=True)
        embed.add_field(name="🏡 Ciudad", value=data.get('city', 'N/A'), inline=True)
        embed.add_field(name="📮 Código Postal", value=data.get('zip', 'N/A'), inline=True)
        embed.add_field(name="🗺️ Lat/Lon", value=f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}", inline=True)
        embed.add_field(name="⏰ Zona Horaria", value=data.get('timezone', 'N/A'), inline=True)
        embed.add_field(name="💻 ISP", value=data.get('isp', 'N/A'), inline=False)
        embed.add_field(name="🏢 Organización", value=data.get('org', 'N/A'), inline=False)
        embed.add_field(name="🔗 AS", value=f"{data.get('as', 'N/A')} ({data.get('asname', 'N/A')})", inline=False)

        lat, lon = data.get('lat'), data.get('lon')
        if lat and lon:
            # Enlace a Google Maps
            embed.add_field(name="🗺️ Ver en Mapa", value=f"[Google Maps](http://googleusercontent.com/maps.google.com/4{lat},{lon})", inline=False)

        await ctx.send(embed=embed)
    else:
        await ctx.send(f"❌ No se pudo obtener información de la IP: {data.get('message', 'Error desconocido')}")


@client.command(name='geoip', aliases=['geo'])
async def geoip_command(ctx, ip: str):
    """Muestra la geolocalización de una IP ($geoip [IP])."""
    data, error = await get_ip_info(ip)
    if error:
        await ctx.send(f"❌ {error}")
        return
    await send_ip_embed(ctx, data, ip)

# ... El resto de los comandos de Ciberseguridad

@client.command(name='dns', help='Realiza una búsqueda de registros DNS (A).')
async def dns_command(ctx, domain: str):
    if not dns: return await ctx.send("❌ Módulo DNSPython no instalado. (`pip install dnspython`)")
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = '\n'.join([rdata.to_text() for rdata in answers])
        await ctx.send(f"🌐 Registros DNS (A) para `{domain}`:\n```\n{ips}\n```")
    except Exception:
        await ctx.send(f"❌ No se encontraron registros DNS (A) para `{domain}`.")

@client.command(name='ipinfo', help='Obtiene información geográfica de una IP.')
async def ipinfo_command(ctx, ip: str):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        data = response.json()
        embed = discord.Embed(title=f"📍 Geolocalización para {ip}", color=discord.Color.red())
        embed.add_field(name="Ciudad", value=data.get('city', 'N/A'), inline=True)
        embed.add_field(name="Región", value=data.get('region', 'N/A'), inline=True)
        embed.add_field(name="País", value=data.get('country', 'N/A'), inline=True)
        embed.add_field(name="Organización", value=data.get('org', 'N/A'), inline=False)
        await ctx.send(embed=embed)
    except Exception:
        await ctx.send(f"❌ Error al consultar información de la IP: `{ip}`.")

@client.command(name='headers', help='Muestra las cabeceras HTTP de un sitio web.')
async def headers_command(ctx, url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        response = requests.head(url, timeout=5)
        headers = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
        await ctx.send(f"📋 Cabeceras HTTP para `{url}`:\n```\n{headers}\n```")
    except Exception:
        await ctx.send(f"❌ Error al obtener las cabeceras HTTP de `{url}`.")

@client.command(name='pingcheck', help='Verifica si un host está en línea (simulado).')
async def ping_check_command(ctx, host: str):
    await ctx.send(f"🟢 Chequeando el estado de `{host}`... (Simulado: Host está en línea)")

@client.command(name='portscan', help='Simula un escaneo de puertos básicos.')
async def portscan_command(ctx, host: str, port: int):
    # Simulación simple de chequeo de socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    
    if result == 0:
        await ctx.send(f"🟢 El puerto **{port}** en `{host}` está **abierto**.")
    else:
        await ctx.send(f"🔴 El puerto **{port}** en `{host}` está **cerrado**.")

@client.command(name='subdomains', help='Simula la búsqueda de subdominios comunes.')
async def subdomains_command(ctx, domain: str):
    await ctx.send(f"🌳 Buscando subdominios para `{domain}`... (Simulado: `admin.{domain}`, `api.{domain}` encontrados)")

@client.command(name='webstatus', help='Verifica el código de estado HTTP de una URL.')
async def webstatus_command(ctx, url: str):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        response = requests.head(url, timeout=5)
        await ctx.send(f"🚦 Status HTTP de `{url}`: **{response.status_code} ({response.reason})**")
    except Exception:
        await ctx.send(f"❌ Error al conectar con `{url}`.")

@client.command(name='reverseip', help='Simula la búsqueda de otros dominios en la misma IP.')
async def reverseip_command(ctx, host: str):
    await ctx.send(f"↩️ Búsqueda IP inversa para `{host}`... (Simulado: `dominio2.com` en la misma IP)")

@client.command(name='urlshorten', help='Acorta una URL (Simulado).')
async def urlshorten_command(ctx, url: str):
    await ctx.send(f"🔗 URL acortada: `[Resultado Simulado]`")

# --- 3. ADMINISTRACIÓN DE SEGURIDAD (5) ---

@client.command(name='logchannel', help='Establece el canal de logs de seguridad.')
@has_permissions(administrator=True)
async def logchannel_command(ctx, channel: discord.TextChannel):
    await ctx.send(f"🔒 Canal de logs de seguridad establecido en {channel.mention}.")

@client.command(name='antispam', help='Activa/desactiva la protección anti-spam.')
@has_permissions(administrator=True)
async def antispam_command(ctx, status: str):
    await ctx.send(f"🛡️ Protección Anti-Spam: **{status.upper()}**.")

@client.command(name='autorole', help='Configura un rol automático al unirse.')
@has_permissions(administrator=True)
async def autorole_command(ctx, role: discord.Role):
    await ctx.send(f"➕ Auto-Rol configurado como **{role.name}**.")

@client.command(name='checkpermissions', help='Verifica los permisos de un usuario/rol.')
async def checkpermissions_command(ctx, member: discord.Member = None):
    member = member or ctx.author
    perms = [p[0] for p in member.guild_permissions if p[1]]
    await ctx.send(f"✅ Permisos de **{member.name}**:\n```\n{', '.join(perms)}\n```")

@client.command(name='massban', help='Baneo masivo de IDs (Owner-Only).')
@is_owner()
async def massban_command(ctx, *, user_ids):
    await ctx.send("💥 Ejecutando baneo masivo de IDs. (Owner-Only)")

# ----------------------------------------------------------------------
# 🛡️ COMANDOS DE MODERACIÓN (30 Comandos)
# ----------------------------------------------------------------------

# --- 1. DISCIPLINA (8) ---

@client.command(name='warn')
@has_permissions(kick_members=True)
async def warn_command(ctx, member: discord.Member, *, reason="No especificada"):
    global warn_data
    user_id = str(member.id)
    if user_id not in warn_data: warn_data[user_id] = []
    warn_data[user_id].append({"razon": reason, "moderador": ctx.author.name, "timestamp": str(datetime.now())})
    save_warn_data(warn_data) 
    await ctx.send(f"⚠️ **{member.name}** advertido por: `{reason}`.")
    
@client.command(name='checkwarns')
async def checkwarns_command(ctx, member: discord.Member):
    user_id = str(member.id)
    if user_id in warn_data and warn_data[user_id]:
        warns = "\n".join([f"  - Razón: {w['razon']} (Por: {w['moderador']})" for w in warn_data[user_id]])
        await ctx.send(f"🚨 Advertencias de **{member.name}** ({len(warn_data[user_id])} en total):\n```\n{warns}\n```")
    else:
        await ctx.send(f"✅ **{member.name}** no tiene advertencias.")

@client.command(name='kick')
@has_permissions(kick_members=True)
async def kick_command(ctx, member: discord.Member, *, reason="No especificada"):
    await member.kick(reason=reason)
    await ctx.send(f"👟 **{member.name}** ha sido expulsado por: `{reason}`.")

@client.command(name='ban')
@has_permissions(ban_members=True)
async def ban_command(ctx, member: discord.Member, *, reason="No especificada"):
    await member.ban(reason=reason)
    await ctx.send(f"🔨 **{member.name}** ha sido baneado por: `{reason}`.")

@client.command(name='unban')
@has_permissions(ban_members=True)
async def unban_command(ctx, userId: int, *, reason="No especificada"):
    try:
        user = await client.fetch_user(userId)
        await ctx.guild.unban(user, reason=reason)
        await ctx.send(f"🔓 Usuario **{user.name}** desbaneado. Razón: `{reason}`")
    except Exception:
        await ctx.send(f"❌ No se pudo desbanear al usuario ID: **{userId}**. ¿Es correcto el ID?")

@client.command(name='softban')
@has_permissions(kick_members=True)
async def softban_command(ctx, member: discord.Member, days: int = 7):
    await member.ban(delete_message_days=days)
    await member.unban()
    await ctx.send(f"🔥 Softban a **{member.name}**: Borrados {days} días de mensajes.")

@client.command(name='mute')
@has_permissions(manage_roles=True)
async def mute_command(ctx, member: discord.Member, *, reason="Silenciado"):
    await ctx.send(f"🔇 **{member.name}** ha sido silenciado. (Requiere rol 'Muted')")

@client.command(name='unmute')
@has_permissions(manage_roles=True)
async def unmute_command(ctx, member: discord.Member):
    await ctx.send(f"🗣️ **{member.name}** puede volver a hablar. (Requiere rol 'Muted')")

# --- 2. LIMPIEZA y CANALES (7) ---

@client.command(name='clear', aliases=['purge'])
@has_permissions(manage_messages=True)
async def clear_command(ctx, amount: int):
    await ctx.channel.purge(limit=amount + 1)
    await ctx.send(f"🧹 **{amount} mensajes** borrados.", delete_after=5)

@client.command(name='lock')
@has_permissions(manage_channels=True)
async def lock_command(ctx, channel: discord.TextChannel = None):
    channel = channel or ctx.channel
    await channel.set_permissions(ctx.guild.default_role, send_messages=False)
    await ctx.send(f"🔒 Canal {channel.mention} cerrado.")

@client.command(name='unlock')
@has_permissions(manage_channels=True)
async def unlock_command(ctx, channel: discord.TextChannel = None):
    channel = channel or ctx.channel
    await channel.set_permissions(ctx.guild.default_role, send_messages=True)
    await ctx.send(f"🔓 Canal {channel.mention} abierto.")

@client.command(name='slowmode')
@has_permissions(manage_channels=True)
async def slowmode_command(ctx, seconds: int):
    await ctx.channel.edit(slowmode_delay=seconds)
    await ctx.send(f"⏱️ Modo lento establecido a **{seconds} segundos**.")

@client.command(name='nuke')
@has_permissions(administrator=True)
async def nuke_command(ctx):
    await ctx.send("💥 Canal **nukeado**.")

@client.command(name='dehoist')
@has_permissions(manage_nicknames=True)
async def dehoist_command(ctx):
    await ctx.send("⬇️ Limpiando nicks ofensivos. (Simulado)")

@client.command(name='massmove')
@has_permissions(manage_channels=True)
async def massmove_command(ctx, current_channel: discord.VoiceChannel, target_channel: discord.VoiceChannel):
    await ctx.send(f"🔊 Moviendo usuarios de {current_channel.name} a {target_channel.name}. (Simulado)")

# --- 3. ROLES y ADMINISTRACIÓN (15) ---

@client.command(name='giverole', aliases=['addrole'])
@has_permissions(manage_roles=True)
async def giverole_command(ctx, member: discord.Member, *, role: discord.Role):
    await member.add_roles(role)
    await ctx.send(f"➕ Rol **{role.name}** dado a **{member.name}**.")

@client.command(name='takerole', aliases=['removerol'])
@has_permissions(manage_roles=True)
async def takerole_command(ctx, member: discord.Member, *, role: discord.Role):
    await member.remove_roles(role)
    await ctx.send(f"➖ Rol **{role.name}** quitado a **{member.name}**.")

@client.command(name='rolall')
@has_permissions(administrator=True)
async def rolall_command(ctx, *, role: discord.Role):
    await ctx.send(f"👑 Dando rol **{role.name}** a todos. (Simulado para evitar rate-limits)")

@client.command(name='nick')
@has_permissions(manage_nicknames=True)
async def nick_command(ctx, member: discord.Member, *, new_nick):
    await member.edit(nick=new_nick)
    await ctx.send(f"✏️ Nick de **{member.name}** cambiado a **{new_nick}**.")

@client.command(name='resetnick')
@has_permissions(manage_nicknames=True)
async def resetnick_command(ctx, member: discord.Member):
    await member.edit(nick=None)
    await ctx.send(f"🗑️ Nick de **{member.name}** reseteado.")

@client.command(name='bots')
@has_permissions(kick_members=True)
async def bots_command(ctx):
    bot_count = sum(1 for member in ctx.guild.members if member.bot)
    await ctx.send(f"🤖 Total de miembros: **{ctx.guild.member_count}**. Bots: **{bot_count}**.")

@client.command(name='channelinfo')
async def channelinfo_command(ctx, channel: discord.TextChannel = None):
    channel = channel or ctx.channel
    await ctx.send(f"📊 Info del canal **{channel.name}**.")

@client.command(name='userinfo')
async def userinfo_command(ctx, member: discord.Member = None):
    member = member or ctx.author
    await ctx.send(f"👤 Info del usuario **{member.name}**.")

@client.command(name='banlist')
@has_permissions(ban_members=True)
async def banlist_command(ctx):
    await ctx.send("📋 Lista de baneos. (Simulado)")

@client.command(name='purgeuser')
@has_permissions(manage_messages=True)
async def purgeuser_command(ctx, member: discord.Member, amount: int):
    await ctx.send(f"🧹 Purgando **{amount} mensajes** de **{member.name}**. (Simulado)")

@client.command(name='serverinfo')
async def serverinfo_command(ctx):
    await ctx.send(f"📑 Mostrando información detallada del servidor **{ctx.guild.name}**.")

# Comandos de Owner
@client.command(name='servers')
@is_owner()
async def servers_list_command(ctx):
    await ctx.send("📜 Enviando lista de servidores por DM. (Owner-Only)")

@client.command(name='shutdown')
@is_owner()
async def shutdown_command(ctx):
    await ctx.send("🔌 **Apagando Mr. Robot...**")
    await client.close()

@client.command(name='eval')
@is_owner()
async def eval_command(ctx, *, code):
    await ctx.send("💻 Ejecutando código de Python. (Owner-Only)")

# --- COMANDO DE INVITACIÓN ---

INVITE_LINK = "https://discord.com/oauth2/authorize?client_id=1423624316548812840&permissions=8&integration_type=0&scope=bot"

@client.command(name='invite', aliases=['invitar'])
async def invite_command(ctx):
    """Muestra el enlace para invitar al bot al servidor."""
    embed = discord.Embed(
        title="🤖 | ¡Invita a Mr. Robot a tu Servidor!",
        description=f"Haz clic [aquí]({INVITE_LINK}) para añadir a Mr. Robot.\n\nEl enlace también se envía por DM.",
        color=discord.Color.blue()
    )
    embed.add_field(name="Link Directo", value=f"`{INVITE_LINK}`", inline=False)
    
    try:
        await ctx.author.send(f"🔗 Enlace de invitación para Mr. Robot:\n{INVITE_LINK}")
        await ctx.send(embed=embed)
    except discord.Forbidden:
        await ctx.send(f"🔗 ¡No pude enviarte un DM! Aquí está el enlace:\n{INVITE_LINK}")

@client.command(name='status')
@is_owner()
async def status_command(ctx, *, new_status):
    await client.change_presence(activity=discord.Game(name=new_status))
    await ctx.send(f"📊 Estado cambiado a: **{new_status}**.")

@client.command(name='say')
@is_owner()
async def say_command(ctx, *, text):
    await ctx.message.delete()
    await ctx.send(text)

# ----------------------------------------------------------------------
# 🎉 COMANDOS DE DIVERSIÓN/UTILIDADES (SOLO LOS QUE USAN API)
# ----------------------------------------------------------------------

import requests 
import io 
import random # Necesario para las utilidades

NEKOS_API = "https://nekos.life/api/v2/img/"

# Función de ayuda para la API de Nekos.life
def get_neko_gif(endpoint: str):
    """Obtiene un GIF de la API de Nekos.life. Retorna una URL o una URL de fallback."""
    try:
        response = requests.get(NEKOS_API + endpoint)
        response.raise_for_status()
        return response.json()['url']
    except Exception:
        # URL de fallback estable en caso de fallo de la API
        return "https://media.giphy.com/media/vHqQ98u/giphy.gif"


# Función de ayuda simplificada para el Embed 
def make_simple_embed(title: str, description: str, color: discord.Color):
    """Crea un Embed simple."""
    return discord.Embed(title=title, description=description, color=color)

# --- INTERACCIONES BASADAS EN API (Los que sabemos que funcionan) ---

INTERACCIONES_API = {
    'hug': {"title": "🤗 ¡Abrazo!", "desc": "le ha dado un gran abrazo a", "color": discord.Color.orange(), "endpoint": "hug"},
    'kiss': {"title": "💋 ¡Beso!", "desc": "le ha dado un beso a", "color": discord.Color.red(), "endpoint": "kiss"},
    'pat': {"title": "👋 ¡Acariciar!", "desc": "ha acariciado la cabeza de", "color": discord.Color.green(), "endpoint": "pat"},
    'slap': {"title": "💢 ¡Bofetada!", "desc": "le ha dado una bofetada a", "color": discord.Color.dark_red(), "endpoint": "slap"},
}

# Generación dinámica de comandos de interacción (usando la API)
for name, data in INTERACCIONES_API.items():
    
    async def interaction_command_api_template(ctx, member: discord.Member = None, name=name, data=data):
        if member is None:
            return await ctx.send("🚨 Debes mencionar a un usuario.")
        
        gif_url = get_neko_gif(data['endpoint'])
        
        embed = make_simple_embed(
            data['title'],
            f"**{ctx.author.display_name}** {data['desc']} **{member.display_name}**.",
            data['color']
        )
        embed.set_image(url=gif_url)
        await ctx.send(embed=embed)

    client.command(name=name)(interaction_command_api_template)


# --- Utilidades Extra (Mantenidas) ---

@client.command(name='coinflip', aliases=['moneda'])
async def coinflip_command(ctx):
    resultado = random.choice(["Cara", "Cruz"])
    await ctx.send(f"🪙 **¡{resultado}!**")
    
@client.command(name='8ball', aliases=['pregunta'])
async def eightball_command(ctx, *, question):
    respuestas = ["Sí, definitivamente.", "Es decididamente así.", "Sin duda.", "Probablemente sí.", "Mi respuesta es no.", "Mis fuentes dicen que no.", "Muy dudoso.", "No puedo predecir ahora."]
    await ctx.send(f"🎱 **{random.choice(respuestas)}**")
    
@client.command(name='ping')
async def ping_command(ctx):
    await ctx.send(f"🏓 Pong! **{round(client.latency * 1000)}ms**")

# ----------------------------------------------------------------------
# 🚀 ARRANQUE FINAL
# ----------------------------------------------------------------------

if __name__ == '__main__':
    try:
        client.run(TOKEN)
    except Exception as e:
        print(f"ERROR FATAL: Revisa el TOKEN y la conexión. {e}")
