"""
Estágio [3] + [4] + [5] - Probe com fallback para navegador real
"""
from typing import Optional
from funnel_recon.legacy.cloaker_probe import probe_with_curl  # seu código existente
from funnel_recon.browser_real import fetch_with_browser, is_bounced_advanced
from funnel_recon.signals import is_bounced  # sua função existente

def probe_url(
    url: str, 
    proxy: Optional[str] = None,
    use_js_fallback: bool = True,
    force_browser: bool = False
) -> dict:
    """
    Orquestrador de probe com fallback inteligente.
    
    Fluxo:
    1. Tenta com curl_cffi (seu código)
    2. Se detectar despejo → tenta com Playwright
    3. Se Playwright falhar → retorna resultado do curl
    
    Args:
        url: URL completa para analisar
        proxy: "socks5://user:pass@host:porta" ou None
        use_js_fallback: Se True, tenta Playwright ao detectar despejo
        force_browser: Se True, usa Playwright diretamente
    
    Returns:
        dict: {
            "html": str,
            "method": "curl_cffi" | "playwright" | "fallback_failed",
            "proxy_used": str | None,
            "bounced": bool,
            "bounce_reason": str,
            "curl_result": dict | None,  # se usou fallback
        }
    """
    print(f"\n🔍 [Probe] Analisando: {url}")
    if proxy:
        print(f"   Proxy: {proxy.split('@')[-1] if '@' in proxy else proxy}")
    
    # Caso force_browser, vai direto para o navegador
    if force_browser:
        print("   ⏩ Forçando uso de navegador real...")
        browser_result = fetch_with_browser(url, proxy=proxy)
        return {
            "html": browser_result.get("html", ""),
            "method": "playwright",
            "proxy_used": proxy,
            "bounced": False,
            "bounce_reason": "",
            "curl_result": None,
            "url": browser_result.get("url", url),
            "error": browser_result.get("error"),
        }
    
    # 1. Tenta com curl_cffi (seu código existente)
    print("   📡 Tentando com curl_cffi...")
    curl_result = probe_with_curl(url, proxy=proxy)
    
    if not curl_result:
        print("   ❌ curl_cffi falhou completamente")
        return {
            "html": "",
            "method": "curl_cffi",
            "proxy_used": proxy,
            "bounced": True,
            "bounce_reason": "curl_cffi_falhou",
            "curl_result": None,
        }
    
    html = curl_result.get("html", "")
    
    # 2. Detecta se é despejo
    # Usa sua função existente + a avançada
    bounced, reason = is_bounced_advanced(html)
    if not bounced:
        # Tenta a função existente do seu código
        bounced = is_bounced(html)  # sua função em signals.py
        if bounced:
            reason = "detectado pela função legada"
    
    if bounced:
        print(f"   🚨 Despejo detectado: {reason}")
        
        if use_js_fallback:
            print("   🔄 Tentando fallback com navegador real (Playwright)...")
            browser_result = fetch_with_browser(url, proxy=proxy)
            
            if browser_result and browser_result.get("html"):
                print("   ✅ Fallback com navegador real bem-sucedido!")
                return {
                    "html": browser_result["html"],
                    "method": "playwright",
                    "proxy_used": proxy,
                    "bounced": False,
                    "bounce_reason": "",
                    "curl_result": curl_result,
                    "url": browser_result.get("url", url),
                    "error": None,
                }
            else:
                print("   ❌ Fallback com navegador real falhou")
                # Retorna o resultado do curl mesmo sendo despejo
                return {
                    "html": html,
                    "method": "curl_cffi_fallback_failed",
                    "proxy_used": proxy,
                    "bounced": True,
                    "bounce_reason": f"{reason} (fallback falhou)",
                    "curl_result": curl_result,
                    "error": browser_result.get("error") if browser_result else "fallback_failed",
                }
        else:
            print("   ⏭️ Fallback desabilitado, mantendo resultado do curl")
            return {
                "html": html,
                "method": "curl_cffi",
                "proxy_used": proxy,
                "bounced": True,
                "bounce_reason": reason,
                "curl_result": None,
            }
    else:
        print("   ✅ Sem despejo detectado")
        return {
            "html": html,
            "method": "curl_cffi",
            "proxy_used": proxy,
            "bounced": False,
            "bounce_reason": "",
            "curl_result": None,
        }
