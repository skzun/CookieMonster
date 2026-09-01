"""Classification: classifica um AuthContext em uma das 7 categorias
estendidas (M6.0), substituindo a saida binaria CONFIRMED/UNKNOWN.

Arvore (ordem importa: a primeira regra que casa vence):

1. bot_challenge_detected no inj e nao no baseline       -> BOT_BLOCKED  0.85
2. inj.login_redirect                                     -> ANONYMOUS   0.85
3. inj.api_anon_status (401/403) sem base                 -> ANONYMOUS   0.80
4. identity_diff (user_id/name/email no inj, nao no base) E
   (api_authenticated OU authenticated_ui OU ui_markers)
   E NAO tem IdP bloqueante                              -> AUTHENTICATED 0.90
4a. identity_diff + IdP detected + sem UI confirmada      -> IDP_BOUND    0.85
4b. identity_diff + mfa_challenge_detected                -> MFA_BLOCKED  0.85
5. inj.api_authenticated sem base                         -> AUTHENTICATED 0.85
6. inj.authenticated_ui ou ui_markers sem base            -> CONTEXT_BOUND 0.70
7. inj.session_token presente mas UI nao confirma         -> CONTEXT_BOUND 0.65
8. nenhum dos acima                                      -> INCONCLUSIVE 0.30

Cada classificacao registra:
- AuthClassification (enum)
- confidence (0-1)
- reason (string canonica)
- hints (lista de marcadores secundarios)
- context_dependencies (lista de dependencias suspeitas)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .context import (
    AuthClassification,
    AuthContext,
    AuthMechanism,
    Evidence,
    IdentityProvider,
    SessionType,
)


def _evidence_has(ctx: AuthContext, type_prefix: str) -> bool:
    return any(ev.type.startswith(type_prefix) for ev in ctx.evidence)


def _evidence_count(ctx: AuthContext, type_prefix: str) -> int:
    return sum(1 for ev in ctx.evidence if ev.type.startswith(type_prefix))


def _classify_observation(observation: Dict[str, Any], target: str) -> Dict[str, Any]:
    """Wrapper de compatibilidade: classifica uma observacao crua (dict).

    Retorna dict com: state, confidence, reason, hints, differential.
    Para uso em integracao com o pipeline antigo (auth_state.py).
    """
    # Cria AuthContext via detector.
    from .detector import detect_all
    ctx = detect_all(observation, target)

    # Extrai sinais do payload injetado (keys esperadas: api_user_id_present,
    # api_authenticated, authenticated_ui, login_redirect, api_anon_status, etc).
    inj = observation.get("injected_evidence") or {}
    base = observation.get("baseline_evidence") or {}
    result = classify(inj, base, ctx)
    result["auth_context"] = ctx.to_dict()
    return result


def classify(inj: Dict[str, Any], base: Dict[str, Any], ctx: AuthContext) -> Dict[str, Any]:
    """Classifica o replay a partir de evidencias injetadas/baseline + AuthContext.

    Retorna dict com: state, confidence, reason, hints, differential,
    context_dependencies, api_only_confirmed.
    """
    inj_ce_count = len(inj.get("console_errors") or [])
    base_ce_count = len(base.get("console_errors") or [])
    inj_rf_count = len(inj.get("request_failures") or [])
    base_rf_count = len(base.get("request_failures") or [])
    runtime_degraded = (
        (inj_ce_count > base_ce_count and inj_ce_count > 0)
        or (inj_rf_count > base_rf_count and inj_rf_count > 0)
    )

    inj_login = bool(inj.get("login_redirect"))
    inj_anon = bool(inj.get("api_anon_status"))
    base_anon = bool(base.get("api_anon_status"))
    identity_diff = (
        (inj.get("api_user_id_present") and not base.get("api_user_id_present"))
        or (inj.get("api_user_name_present") and not base.get("api_user_name_present"))
        or (inj.get("api_user_email_present") and not base.get("api_user_email_present"))
    )
    inj_api = bool(inj.get("api_authenticated"))
    base_api = bool(base.get("api_authenticated"))
    inj_ui = bool(inj.get("authenticated_ui"))
    base_ui = bool(base.get("authenticated_ui"))
    inj_markers = bool(inj.get("ui_markers"))
    base_markers = bool(base.get("ui_markers"))
    has_session_token = bool(inj.get("session_token") or inj.get("api_responses_inspected"))

    # Hint de "api_only" (ja existe na logica legada).
    api_only = (
        identity_diff
        and not (inj_api or inj_ui or inj_markers)
    )

    # --- Arvore de classificacao (M6.0) ---

    classification = AuthClassification.INCONCLUSIVE
    confidence = 0.30
    reason = ""
    hints: List[str] = []
    dependencies: List[str] = []

    # 1) Bot challenge
    if ctx.bot_challenge_detected and not _baseline_has_bot(observation := {"base": base, "inj": inj}):
        classification = AuthClassification.BOT_BLOCKED
        confidence = 0.85
        reason = "anti_bot_challenge_detected"
        hints.append("bot_challenge")
    # 2) Login redirect explicito
    elif inj_login:
        classification = AuthClassification.ANONYMOUS
        confidence = 0.85
        reason = "session_cookie_rejected"
        hints.append("login_redirect")
    # 3) API anon (401/403)
    elif inj_anon and not base_anon:
        classification = AuthClassification.ANONYMOUS
        confidence = 0.80
        reason = "api_rejected"
        hints.append("api_anon_status")
    # 4) Identity diferencial (CONFIRMED real)
    elif identity_diff and not inj_login and (
        inj_api or inj_ui or inj_markers
    ):
        # 4a) Se IdP foi detectado e UI nao confirmou: IDP_BOUND
        if ctx.identity_provider not in (IdentityProvider.NONE, IdentityProvider.UNKNOWN) and not inj_ui:
            classification = AuthClassification.IDP_BOUND
            confidence = 0.85
            reason = f"identity_provider_boundary:{ctx.identity_provider.value}"
            hints.append("idp_reference")
            hints.append("api_only")
            dependencies.append("idp")
        # 4b) Se MFA foi detectado: MFA_BLOCKED
        elif ctx.mfa_challenge_detected:
            classification = AuthClassification.MFA_BLOCKED
            confidence = 0.85
            reason = "mfa_required_by_idp"
            hints.append("mfa_challenge")
            dependencies.append("mfa")
        # 4c) Caso contrario: AUTHENTICATED
        else:
            classification = AuthClassification.AUTHENTICATED
            confidence = 0.90
            reason = "identity_confirmed"
    # 5) API autenticada sem base
    elif inj_api and not base_api and not inj_login:
        if ctx.identity_provider not in (IdentityProvider.NONE, IdentityProvider.UNKNOWN) and not inj_ui:
            classification = AuthClassification.IDP_BOUND
            confidence = 0.80
            reason = f"api_only_idp:{ctx.identity_provider.value}"
            hints.append("idp_reference")
            hints.append("api_only")
            dependencies.append("idp")
        elif ctx.mfa_challenge_detected:
            classification = AuthClassification.MFA_BLOCKED
            confidence = 0.80
            reason = "api_authenticated_but_mfa_required"
            hints.append("mfa_challenge")
            dependencies.append("mfa")
        else:
            classification = AuthClassification.AUTHENTICATED
            confidence = 0.85
            reason = "api_authenticated"
    # 6) UI autenticada sem base
    elif (inj_ui and not base_ui) or (inj_markers and not base_markers) and not inj_login:
        classification = AuthClassification.CONTEXT_BOUND
        confidence = 0.70
        reason = "ui_authenticated_no_identity"
        hints.append("authenticated_ui")
        dependencies.append("browser_state")
    # 7) Session token presente mas UI/API nao confirma
    elif has_session_token and not inj_api and not inj_ui and not inj_login:
        classification = AuthClassification.CONTEXT_BOUND
        confidence = 0.65
        reason = "session_token_present_no_state"
        hints.append("session_token")
        dependencies.append("cookie_only")
    # 8) Nada
    else:
        classification = AuthClassification.INCONCLUSIVE
        confidence = 0.30
        reason = "insufficient_evidence"

    # Runtime degradado reduz confianca (evita falso positivo).
    if runtime_degraded and classification in (
        AuthClassification.AUTHENTICATED,
        AuthClassification.CONTEXT_BOUND,
        AuthClassification.IDP_BOUND,
        AuthClassification.MFA_BLOCKED,
    ):
        confidence = max(0.30, confidence - 0.25)
        hints.append("runtime_degraded")
    elif runtime_degraded and classification == AuthClassification.ANONYMOUS:
        confidence = min(0.90, confidence + 0.05)

    # Atualiza ctx.
    ctx.classification = classification
    ctx.confidence = confidence
    ctx.reason = reason
    ctx.hints = hints
    ctx.context_dependencies = dependencies

    # Identity observada (se houver).
    if identity_diff:
        ctx.identity_observed = {
            "id": inj.get("identity_id"),
            "name": inj.get("identity_name"),
            "email": inj.get("identity_email"),
        }

    return {
        "state": classification.value,
        "confidence": confidence,
        "reason": reason,
        "hints": hints,
        "context_dependencies": dependencies,
        "api_only_confirmed": api_only,
        "bot_challenge_detected": ctx.bot_challenge_detected,
        "mfa_challenge_detected": ctx.mfa_challenge_detected,
        "auth_mechanism": ctx.auth_mechanism.value,
        "identity_provider": ctx.identity_provider.value,
        "session_type": ctx.session_type.value,
    }


def _baseline_has_bot(observation: Dict[str, Any]) -> bool:
    """Helper: verifica se o baseline tambem teve bot challenge."""
    # Em M6.0 nao temos baseline.bot separadamente; usamos heuristica simples.
    # Sera expandido quando integrarmos com replay real.
    return False


# --- Helpers de integracao com o pipeline legado ---

def classify_legacy(inj: Dict[str, Any], base: Dict[str, Any],
                    domain: str = "") -> Dict[str, Any]:
    """Wrapper que cria AuthContext e classifica, retornando dict no formato
    esperado pelo auth_state.py legado.

    Mantem compatibilidade com runs antigos.
    """
    observation = {
        "injected_evidence": inj,
        "baseline_evidence": base,
    }
    return _classify_observation(observation, domain)
