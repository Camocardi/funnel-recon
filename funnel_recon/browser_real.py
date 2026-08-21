"""
Estágio [5] - Browser real com fingerprint JS
"""
import time
from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

def fetch_with_browser(url: str, proxy: str = None, timeout: int = 30000) -> dict:
    """
    Busca URL com Chromium headless + técnicas anti-detecção.
    
    Args:
        url: URL para carregar
        proxy: Ex: "socks5://user:pass@host:porta" ou "http://user:pass@host:porta"
        timeout: Timeout em ms
    
    Returns:
        dict: {"html": str, "method": "playwright", "url": str, "error": str|None}
    """
    print(f"🌐 [Browser Real] Iniciando para: {url}")
    
    if proxy:
        print(f"   Proxy: {proxy.split('@')[-1] if '@' in proxy else proxy}")  # oculta senha
    
    with sync_playwright() as p:
        # Configurações para parecer um navegador real
        launch_options = {
            "headless": True,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-web-security",  # alguns sites precisam
                "--disable-features=IsolateOrigins,site-per-process",
            ]
        }
        
        context_options = {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "viewport": {"width": 1366, "height": 768},
            "locale": "en-US",
            "timezone_id": "America/New_York",
            "extra_http_headers": {
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            },
            "java_script_enabled": True,
        }
        
        if proxy:
            context_options["proxy"] = {"server": proxy}
        
        browser = p.chromium.launch(**launch_options)
        context = browser.new_context(**context_options)
        
        # Aplica técnicas stealth (canvas, WebGL, etc.)
        page = context.new_page()
        Stealth().apply_stealth_sync(page)
        
        try:
            # Carrega a página
            page.goto(url, wait_until="networkidle", timeout=timeout)
            
            # Pequeno delay para garantir execução do JS
            time.sleep(2)
            
            html = page.content()
            final_url = page.url
            
            print(f"✅ [Browser Real] Página carregada: {final_url}")
            print(f"   Tamanho HTML: {len(html):,} caracteres")
            
            return {
                "html": html,
                "method": "playwright",
                "url": final_url,
                "error": None
            }
            
        except Exception as e:
            print(f"❌ [Browser Real] Falha: {e}")
            return {
                "html": "",
                "method": "playwright",
                "url": url,
                "error": str(e)
            }
        finally:
            browser.close()


def is_bounced_advanced(html: str) -> tuple[bool, str]:
    """
    Detecta se a página é um "despejo" (bounce) com sinais avançados.
    
    Retorna: (True/False, motivo)
    """
    if not html or len(html) < 100:
        return True, "conteúdo muito curto"
    
    html_lower = html.lower()
    
    # Sinais fortes de despejo
    strong_signals = [
        ("cwc.edu", "despejo para faculdade"),
        ("central wyoming college", "despejo para faculdade"),
        ("tarot", "despejo para tarô"),
        ("404 not found", "página não encontrada"),
        ("access denied", "acesso negado"),
        ("please enable javascript", "JS desabilitado"),
        ("your browser does not support", "navegador incompatível"),
        ("cloudflare", "página de bloqueio Cloudflare"),
    ]
    
    for signal, reason in strong_signals:
        if signal in html_lower:
            return True, reason
    
    # Sinais fracos (suspeitos)
    weak_signals = [
        ("cpanel", "painel de hospedagem"),
        ("webmail", "webmail"),
        ("plesk", "painel Plesk"),
        ("default page", "página padrão"),
    ]
    
    for signal, reason in weak_signals:
        if signal in html_lower:
            return True, f"suspeito: {reason}"
    
    return False, "conteúdo parece legítimo"
