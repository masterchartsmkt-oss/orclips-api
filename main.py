"""
OrClips SaaS API — Servidor de Licenciamento
=============================================
FastAPI + SQLAlchemy + JWT + Hardware Fingerprint
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
import bcrypt
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, Float, ForeignKey, Text, Enum as SAEnum
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
import enum

# =====================================================
# CONFIGURAÇÃO
# =====================================================

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres.wglskacblzzzpuxumndg:Aspirina2020250525@aws-1-us-east-2.pooler.supabase.com:6543/postgres")

# CORREÇÃO: Se a variável de ambiente tiver o host antigo, forçar o correto
if "pzvsecxiehvlafgtserc" in DATABASE_URL:
    DATABASE_URL = "postgresql://postgres.wglskacblzzzpuxumndg:Aspirina2020250525@aws-1-us-east-2.pooler.supabase.com:6543/postgres"

SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7
REFRESH_TOKEN_EXPIRE_DAYS = 30

# =====================================================
# BANCO DE DADOS
# =====================================================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class PlanType(str, enum.Enum):
    FREE = "free"
    PREMIUM = "premium"
    DIAMANTE = "diamante"


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    nome = Column(String(255), nullable=False)
    senha_hash = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.USER, nullable=False)
    plano = Column(String(20), default=PlanType.FREE, nullable=False)
    is_active = Column(Boolean, default=True)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    atualizado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relacionamentos
    license = relationship("License", back_populates="user", uselist=False)
    subscription = relationship("Subscription", back_populates="user", uselist=False)
    usage_logs = relationship("UsageLog", back_populates="user")


class License(Base):
    __tablename__ = "licenses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    hardware_fingerprint = Column(String(128), nullable=True)
    ativado_em = Column(DateTime, nullable=True)
    ultima_verificacao = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    reset_count = Column(Integer, default=0)
    ultimo_reset = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="license")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    plano = Column(String(20), default=PlanType.FREE, nullable=False)
    inicio = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    vencimento = Column(DateTime, nullable=True)
    payment_id = Column(String(255), nullable=True)  # ID do Stripe/MercadoPago
    payment_status = Column(String(50), default="none")  # none, active, cancelled, expired
    valor = Column(Float, default=0.0)

    user = relationship("User", back_populates="subscription")


class UsageLog(Base):
    __tablename__ = "usage_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    acao = Column(String(50), nullable=False)  # "dublagem", "garimpo", "gerador"
    detalhes = Column(Text, nullable=True)
    criado_em = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="usage_logs")


# Criar tabelas
Base.metadata.create_all(bind=engine)


# =====================================================
# SEGURANÇA
# =====================================================

def hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verificar_senha(senha: str, hash_str: str) -> bool:
    return bcrypt.checkpw(senha.encode("utf-8"), hash_str.encode("utf-8"))


def criar_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decodificar_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado"
        )


# =====================================================
# DEPENDÊNCIAS
# =====================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    authorization: str = Header(..., description="Bearer <token>"),
    db: Session = Depends(get_db)
) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Formato de token inválido")
    
    token = authorization.replace("Bearer ", "")
    payload = decodificar_token(token)
    
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Token sem identificação")
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuário não encontrado ou inativo")
    
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return current_user


# =====================================================
# SCHEMAS (Pydantic)
# =====================================================

class RegisterRequest(BaseModel):
    nome: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    senha: str = Field(..., min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    senha: str
    hardware_fingerprint: str = Field(..., min_length=16, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    plano: str
    nome: str
    expires_in: int  # segundos


class RefreshRequest(BaseModel):
    refresh_token: str
    hardware_fingerprint: str


class VerifyLicenseRequest(BaseModel):
    hardware_fingerprint: str


class UserOut(BaseModel):
    id: int
    email: str
    nome: str
    plano: str
    role: str
    is_active: bool
    criado_em: datetime
    hardware_fingerprint: Optional[str] = None
    usage_count: int = 0

    class Config:
        from_attributes = True


class AdminUpdateUser(BaseModel):
    plano: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[str] = None


class AdminResetFingerprint(BaseModel):
    user_id: int


class UsageLogOut(BaseModel):
    id: int
    acao: str
    detalhes: Optional[str]
    criado_em: datetime

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    total_users: int
    users_free: int
    users_premium: int
    users_diamante: int
    users_active: int
    total_dublagens: int
    revenue_monthly: float


# =====================================================
# LIMITES POR PLANO
# =====================================================

PLAN_LIMITS = {
    PlanType.FREE: {
        "dublagens_max": 2,
        "tempo_max_min": 10,
        "garimpo": False,
        "gerador": False,
    },
    PlanType.PREMIUM: {
        "dublagens_max": -1,  # ilimitado
        "tempo_max_min": -1,
        "garimpo": False,
        "gerador": False,
    },
    PlanType.DIAMANTE: {
        "dublagens_max": -1,
        "tempo_max_min": -1,
        "garimpo": True,
        "gerador": True,
    },
}


# =====================================================
# APP FASTAPI
# =====================================================

app = FastAPI(
    title="OrClips SaaS API",
    description="API de licenciamento e gerenciamento do OrClips",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Em produção, restrinja aos domínios corretos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# EVENTO DE STARTUP — Criar admin padrão
# =====================================================

@app.on_event("startup")
def create_default_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@orclips.com").first()
        if not admin:
            admin = User(
                email="admin@orclips.com",
                nome="Admin OrClips",
                senha_hash=hash_senha("admin123456"),
                role=UserRole.ADMIN,
                plano=PlanType.DIAMANTE,
                is_active=True
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            
            # Criar licença e subscription para admin
            db.add(License(user_id=admin.id, is_active=True))
            db.add(Subscription(user_id=admin.id, plano=PlanType.DIAMANTE, payment_status="active"))
            db.commit()
            print("✅ Admin padrão criado: admin@orclips.com / admin123456")
    finally:
        db.close()


# =====================================================
# ROTAS — AUTENTICAÇÃO
# =====================================================

@app.post("/auth/register", response_model=dict, tags=["Auth"])
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Criar nova conta (plano Free)"""
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")

    user = User(
        email=req.email,
        nome=req.nome,
        senha_hash=hash_senha(req.senha),
        plano=PlanType.FREE,
        role=UserRole.USER
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Criar licença e subscription vazias
    db.add(License(user_id=user.id))
    db.add(Subscription(user_id=user.id, plano=PlanType.FREE))
    db.commit()

    return {"message": "Conta criada com sucesso", "user_id": user.id}


@app.post("/auth/login", response_model=TokenResponse, tags=["Auth"])
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """
    Login com validação de hardware fingerprint.
    - Primeiro login: vincula o fingerprint ao usuário
    - Logins seguintes: rejeita se fingerprint diferente
    """
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verificar_senha(req.senha, user.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Conta desativada. Contacte o suporte.")

    # Verificar fingerprint (ADMIN PULA — pode logar de qualquer PC)
    license = db.query(License).filter(License.user_id == user.id).first()
    if not license:
        license = License(user_id=user.id)
        db.add(license)
        db.commit()
        db.refresh(license)

    if user.role == UserRole.ADMIN:
        # Admin não tem restrição de fingerprint
        license.ultima_verificacao = datetime.now(timezone.utc)
        license.is_active = True
        db.commit()
    elif license.hardware_fingerprint is None:
        # Primeira ativação — vincular este PC
        license.hardware_fingerprint = req.hardware_fingerprint
        license.ativado_em = datetime.now(timezone.utc)
        license.ultima_verificacao = datetime.now(timezone.utc)
        license.is_active = True
        db.commit()
    elif license.hardware_fingerprint != req.hardware_fingerprint:
        # PC diferente — BLOQUEAR
        raise HTTPException(
            status_code=403,
            detail="Esta licença já está vinculada a outro computador. "
                   "Solicite um reset de fingerprint ao suporte."
        )
    else:
        # Mesmo PC — atualizar última verificação
        license.ultima_verificacao = datetime.now(timezone.utc)
        db.commit()

    # Gerar tokens
    access_token = criar_token(
        data={"sub": str(user.id), "email": user.email, "plano": user.plano, "role": user.role},
        expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    )
    refresh_token = criar_token(
        data={"sub": str(user.id), "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        plano=user.plano,
        nome=user.nome,
        expires_in=ACCESS_TOKEN_EXPIRE_DAYS * 86400
    )


@app.post("/auth/refresh", response_model=TokenResponse, tags=["Auth"])
def refresh_token(req: RefreshRequest, db: Session = Depends(get_db)):
    """Renovar tokens usando refresh_token + fingerprint"""
    payload = decodificar_token(req.refresh_token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token de refresh inválido")

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuário não encontrado ou inativo")

    # Verificar fingerprint (admin pula)
    license = db.query(License).filter(License.user_id == user.id).first()
    if user.role != UserRole.ADMIN:
        if license and license.hardware_fingerprint and license.hardware_fingerprint != req.hardware_fingerprint:
            raise HTTPException(status_code=403, detail="Fingerprint não confere")

    access_token = criar_token(
        data={"sub": str(user.id), "email": user.email, "plano": user.plano, "role": user.role},
        expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    )
    new_refresh = criar_token(
        data={"sub": str(user.id), "type": "refresh"},
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        plano=user.plano,
        nome=user.nome,
        expires_in=ACCESS_TOKEN_EXPIRE_DAYS * 86400
    )


# =====================================================
# ROTAS — LICENÇA
# =====================================================

@app.post("/license/verify", tags=["License"])
def verify_license(
    req: VerifyLicenseRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verificação periódica de licença (o app chama a cada X horas).
    Confirma se a conta está ativa, plano válido, e fingerprint bate.
    """
    license = db.query(License).filter(License.user_id == current_user.id).first()

    if not license or not license.is_active:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Licença inativa")

    if current_user.role != UserRole.ADMIN:
        if license and license.hardware_fingerprint != req.hardware_fingerprint:
            raise HTTPException(status_code=403, detail="Fingerprint não confere")

    # Verificar vencimento da subscription
    sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
    if sub and sub.vencimento and sub.vencimento < datetime.now(timezone.utc):
        # Subscription vencida — rebaixar para free
        current_user.plano = PlanType.FREE
        sub.plano = PlanType.FREE
        sub.payment_status = "expired"
        db.commit()

    license.ultima_verificacao = datetime.now(timezone.utc)
    db.commit()

    limits = PLAN_LIMITS.get(current_user.plano, PLAN_LIMITS[PlanType.FREE])
    usage_count = db.query(UsageLog).filter(
        UsageLog.user_id == current_user.id,
        UsageLog.acao == "dublagem"
    ).count()

    return {
        "status": "active",
        "plano": current_user.plano,
        "nome": current_user.nome,
        "limits": limits,
        "usage": {"dublagens": usage_count},
        "verified_at": datetime.now(timezone.utc).isoformat()
    }


@app.post("/license/reset-fingerprint", tags=["License"])
def self_reset_fingerprint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Permite ao próprio usuário resetar fingerprint 1x a cada 30 dias.
    Útil quando troca de computador.
    """
    license = db.query(License).filter(License.user_id == current_user.id).first()
    if not license:
        raise HTTPException(status_code=404, detail="Licença não encontrada")

    if license.ultimo_reset:
        dias_desde_reset = (datetime.now(timezone.utc) - license.ultimo_reset).days
        if dias_desde_reset < 30:
            raise HTTPException(
                status_code=429,
                detail=f"Reset disponível em {30 - dias_desde_reset} dia(s)"
            )

    license.hardware_fingerprint = None
    license.ativado_em = None
    license.reset_count += 1
    license.ultimo_reset = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Fingerprint resetado. Faça login no novo computador."}


# =====================================================
# ROTAS — USO
# =====================================================

@app.post("/usage/log", tags=["Usage"])
def log_usage(
    acao: str,
    detalhes: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Registrar uso de uma funcionalidade (chamado pelo app antes de executar)"""
    limits = PLAN_LIMITS.get(current_user.plano, PLAN_LIMITS[PlanType.FREE])

    if acao == "dublagem":
        usage_count = db.query(UsageLog).filter(
            UsageLog.user_id == current_user.id,
            UsageLog.acao == "dublagem"
        ).count()
        max_dub = limits["dublagens_max"]
        if max_dub != -1 and usage_count >= max_dub:
            raise HTTPException(status_code=403, detail="Limite de dublagens atingido para o seu plano")

    elif acao == "garimpo" and not limits["garimpo"]:
        raise HTTPException(status_code=403, detail="Garimpo requer plano Diamante")

    elif acao == "gerador" and not limits["gerador"]:
        raise HTTPException(status_code=403, detail="Gerador Pro requer plano Diamante")

    log = UsageLog(user_id=current_user.id, acao=acao, detalhes=detalhes)
    db.add(log)
    db.commit()

    return {"message": "Uso registrado", "acao": acao}


@app.get("/usage/my", response_model=list[UsageLogOut], tags=["Usage"])
def my_usage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Listar histórico de uso do usuário logado"""
    logs = db.query(UsageLog).filter(
        UsageLog.user_id == current_user.id
    ).order_by(UsageLog.criado_em.desc()).limit(50).all()
    return logs


# =====================================================
# ROTAS — PERFIL DO USUÁRIO
# =====================================================

@app.get("/me", tags=["User"])
def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Retorna dados do usuário logado"""
    license = db.query(License).filter(License.user_id == current_user.id).first()
    usage_count = db.query(UsageLog).filter(
        UsageLog.user_id == current_user.id,
        UsageLog.acao == "dublagem"
    ).count()
    sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()

    limits = PLAN_LIMITS.get(current_user.plano, PLAN_LIMITS[PlanType.FREE])

    return {
        "id": current_user.id,
        "email": current_user.email,
        "nome": current_user.nome,
        "plano": current_user.plano,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "criado_em": current_user.criado_em.isoformat() if current_user.criado_em else None,
        "license": {
            "fingerprint_set": license.hardware_fingerprint is not None if license else False,
            "ativado_em": license.ativado_em.isoformat() if license and license.ativado_em else None,
            "reset_count": license.reset_count if license else 0,
        },
        "subscription": {
            "plano": sub.plano if sub else "free",
            "vencimento": sub.vencimento.isoformat() if sub and sub.vencimento else None,
            "payment_status": sub.payment_status if sub else "none",
        },
        "usage": {
            "dublagens": usage_count,
        },
        "limits": limits
    }


@app.put("/me/password", tags=["User"])
def change_password(
    senha_atual: str,
    nova_senha: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Alterar senha"""
    if not verificar_senha(senha_atual, current_user.senha_hash):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")
    if len(nova_senha) < 6:
        raise HTTPException(status_code=400, detail="Nova senha deve ter no mínimo 6 caracteres")

    current_user.senha_hash = hash_senha(nova_senha)
    db.commit()
    return {"message": "Senha alterada com sucesso"}


# =====================================================
# ROTAS — ADMIN
# =====================================================

@app.get("/admin/users", response_model=list[UserOut], tags=["Admin"])
def admin_list_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Listar todos os usuários (admin)"""
    users = db.query(User).order_by(User.criado_em.desc()).all()
    result = []
    for u in users:
        license = db.query(License).filter(License.user_id == u.id).first()
        usage_count = db.query(UsageLog).filter(UsageLog.user_id == u.id).count()
        result.append(UserOut(
            id=u.id,
            email=u.email,
            nome=u.nome,
            plano=u.plano,
            role=u.role,
            is_active=u.is_active,
            criado_em=u.criado_em,
            hardware_fingerprint=license.hardware_fingerprint if license else None,
            usage_count=usage_count
        ))
    return result


@app.put("/admin/users/{user_id}", tags=["Admin"])
def admin_update_user(
    user_id: int,
    updates: AdminUpdateUser,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Atualizar plano, status ou role de um usuário (admin)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    if updates.plano is not None:
        user.plano = updates.plano
        sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
        if sub:
            sub.plano = updates.plano
            if updates.plano != PlanType.FREE:
                sub.vencimento = datetime.now(timezone.utc) + timedelta(days=30)
                sub.payment_status = "active"

    if updates.is_active is not None:
        user.is_active = updates.is_active

    if updates.role is not None:
        user.role = updates.role

    db.commit()
    return {"message": f"Usuário {user.email} atualizado"}


@app.post("/admin/reset-fingerprint", tags=["Admin"])
def admin_reset_fingerprint(
    req: AdminResetFingerprint,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Resetar fingerprint de um usuário (admin)"""
    license = db.query(License).filter(License.user_id == req.user_id).first()
    if not license:
        raise HTTPException(status_code=404, detail="Licença não encontrada")

    license.hardware_fingerprint = None
    license.ativado_em = None
    db.commit()
    return {"message": "Fingerprint resetado pelo admin"}


@app.delete("/admin/users/{user_id}", tags=["Admin"])
def admin_delete_user(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Desativar um usuário (soft delete)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if user.role == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="Não é possível desativar um admin")

    user.is_active = False
    license = db.query(License).filter(License.user_id == user.id).first()
    if license:
        license.is_active = False
    db.commit()
    return {"message": f"Usuário {user.email} desativado"}


@app.get("/admin/stats", response_model=StatsOut, tags=["Admin"])
def admin_stats(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Estatísticas gerais do sistema"""
    total = db.query(User).count()
    free = db.query(User).filter(User.plano == PlanType.FREE).count()
    premium = db.query(User).filter(User.plano == PlanType.PREMIUM).count()
    diamante = db.query(User).filter(User.plano == PlanType.DIAMANTE).count()
    active = db.query(User).filter(User.is_active == True).count()
    dublagens = db.query(UsageLog).filter(UsageLog.acao == "dublagem").count()

    # Revenue = Premium × 19.90 + Diamante × 49.90
    revenue = (premium * 19.90) + (diamante * 49.90)

    return StatsOut(
        total_users=total,
        users_free=free,
        users_premium=premium,
        users_diamante=diamante,
        users_active=active,
        total_dublagens=dublagens,
        revenue_monthly=round(revenue, 2)
    )


# =====================================================
# WEBHOOK — PAGAMENTO (exemplo para Stripe)
# =====================================================

@app.post("/webhooks/payment", tags=["Webhooks"])
async def payment_webhook(payload: dict):
    """
    Webhook para receber notificações de pagamento.
    Adapte para Stripe, MercadoPago, etc.
    """
    # Exemplo simplificado — em produção, valide a assinatura do webhook
    event_type = payload.get("type", "")
    data = payload.get("data", {})

    db = SessionLocal()
    try:
        if event_type == "payment.approved":
            email = data.get("email")
            plano = data.get("plano", "premium")
            payment_id = data.get("payment_id")

            user = db.query(User).filter(User.email == email).first()
            if user:
                user.plano = plano
                sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
                if sub:
                    sub.plano = plano
                    sub.payment_id = payment_id
                    sub.payment_status = "active"
                    sub.vencimento = datetime.now(timezone.utc) + timedelta(days=30)
                    sub.inicio = datetime.now(timezone.utc)
                db.commit()

        elif event_type == "payment.cancelled":
            email = data.get("email")
            user = db.query(User).filter(User.email == email).first()
            if user:
                user.plano = PlanType.FREE
                sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
                if sub:
                    sub.plano = PlanType.FREE
                    sub.payment_status = "cancelled"
                db.commit()

    finally:
        db.close()

    return {"status": "ok"}


# =====================================================
# HEALTH CHECK + VERSÃO
# =====================================================

# Controle de versão do app desktop
APP_VERSION = "1.0.0"
APP_DOWNLOAD_URL = os.getenv("APP_DOWNLOAD_URL", "https://github.com/SEU_USUARIO/orclips-releases/releases/latest/download/OrClips.exe")

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "online",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/app/version", tags=["System"])
def app_version():
    """
    Retorna a versão mais recente do app desktop.
    O app consulta este endpoint ao abrir para verificar se precisa atualizar.
    """
    return {
        "version": APP_VERSION,
        "download_url": APP_DOWNLOAD_URL,
        "changelog": "Melhorias de estabilidade e novos recursos.",
        "required": False  # True = forçar update, False = opcional
    }


@app.put("/admin/app-version", tags=["Admin"])
def update_app_version(
    version: str,
    download_url: str = None,
    changelog: str = None,
    required: bool = False,
    admin: User = Depends(require_admin),
):
    """Atualizar a versão do app e URL de download (admin)"""
    global APP_VERSION, APP_DOWNLOAD_URL
    APP_VERSION = version
    if download_url:
        APP_DOWNLOAD_URL = download_url
    return {"message": f"Versão atualizada para {version}", "download_url": APP_DOWNLOAD_URL}


# =====================================================
# NOTIFICAÇÃO POR EMAIL (Resend / SMTP)
# =====================================================

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "OrClips <noreply@orclips.com>")


def enviar_email(to: str, subject: str, html: str):
    """Envia email via Resend API (se configurado) ou ignora silenciosamente"""
    if not RESEND_API_KEY:
        print(f"[EMAIL] Resend não configurado. Email para {to} não enviado.")
        return False
    
    try:
        import httpx
        resp = httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": EMAIL_FROM,
                "to": [to],
                "subject": subject,
                "html": html
            },
            timeout=10
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"[EMAIL] Erro ao enviar: {e}")
        return False


def email_boas_vindas(nome: str, email: str, senha: str, plano: str):
    """Template de email de boas-vindas com credenciais"""
    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #0A0A0F; color: #F0EFF4; padding: 40px; border-radius: 16px;">
        <div style="text-align: center; margin-bottom: 30px;">
            <div style="width: 56px; height: 56px; border-radius: 16px; background: #8B2FC9; display: inline-flex; align-items: center; justify-content: center; font-size: 24px; color: #fff; font-weight: 700;">◆</div>
            <h1 style="color: #F0EFF4; margin: 12px 0 0;">Bem-vindo ao OrClips!</h1>
        </div>
        <p>Olá <strong>{nome}</strong>,</p>
        <p>Sua conta foi criada com sucesso. Aqui estão suas credenciais de acesso:</p>
        <div style="background: #16161F; border-radius: 12px; padding: 20px; margin: 20px 0;">
            <p style="margin: 4px 0;"><strong>Email:</strong> {email}</p>
            <p style="margin: 4px 0;"><strong>Senha:</strong> {senha}</p>
            <p style="margin: 4px 0; color: #C77DFF;"><strong>Plano:</strong> {plano.upper()}</p>
        </div>
        <p>Para começar:</p>
        <ol>
            <li>Baixe o OrClips no link que recebeu</li>
            <li>Abra o aplicativo e faça login com as credenciais acima</li>
            <li>Aproveite todas as funcionalidades do seu plano!</li>
        </ol>
        <p style="color: #6B6A78; font-size: 12px; margin-top: 30px;">Este é um email automático. Não responda.</p>
    </div>
    """
    enviar_email(email, "Bem-vindo ao OrClips! Suas credenciais de acesso", html)


# =====================================================
# ADMIN — CRIAR CLIENTE COM EMAIL AUTOMÁTICO
# =====================================================

class AdminCreateUser(BaseModel):
    nome: str = Field(..., min_length=2)
    email: EmailStr
    senha: str = Field(..., min_length=6)
    plano: str = "free"
    enviar_email: bool = True


@app.post("/admin/create-user", tags=["Admin"])
def admin_create_user(
    req: AdminCreateUser,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Criar cliente diretamente pelo admin com plano já definido.
    Opcionalmente envia email com credenciais.
    """
    # Verificar se email já existe
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")

    # Criar usuário
    user = User(
        email=req.email,
        nome=req.nome,
        senha_hash=hash_senha(req.senha),
        plano=req.plano,
        role=UserRole.USER
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Criar licença e subscription
    db.add(License(user_id=user.id))
    sub = Subscription(user_id=user.id, plano=req.plano)
    if req.plano != PlanType.FREE:
        sub.payment_status = "active"
        sub.vencimento = datetime.now(timezone.utc) + timedelta(days=30)
    db.add(sub)
    db.commit()

    # Enviar email de boas-vindas
    email_enviado = False
    if req.enviar_email:
        email_boas_vindas(req.nome, req.email, req.senha, req.plano)
        email_enviado = True

    return {
        "message": f"Cliente {req.nome} criado com plano {req.plano}",
        "user_id": user.id,
        "email_enviado": email_enviado,
        "credenciais": {
            "email": req.email,
            "senha": req.senha,
            "plano": req.plano
        }
    }


# =====================================================
# RUN
# =====================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
