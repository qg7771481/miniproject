import sqlalchemy
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from typing import List

DATABASE_URL = "sqlite:///./infohub.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = sqlalchemy.orm.declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    articles = relationship("Article", back_populates="author")


class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100))
    content = Column(Text)
    tags = Column(String)
    author_id = Column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="articles")


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class ArticleCreate(BaseModel):
    title: str = Field(..., example="Що таке FastAPI?")
    content: str
    tags: List[str] = Field(default_factory=list)


class ArticleOut(ArticleCreate):
    id: int
    author_id: int

    class Config:
        from_attributes = True


SECRET_KEY = "qg777"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def create_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise credentials_exception
    return user


app = FastAPI(title="InfoHub")


@app.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["users"],
    summary="Register new user",
    description="Створення нового юзера",
    responses={
        201: {"description": "юзера створено успішно"},
        400: {"description": "емаил вже зареєстрований"},
    },
    operation_id="register-user",
    name="register"
)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = hash_password(user.password)
    new_user = User(email=user.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post(
    "/token",
    tags=["auth"],
    summary="Login and get token",
    description="Отримати токен",
    responses={
        200: {"description": "Успішна авторизація"},
        400: {"description": "Невірно"},
    },
    operation_id="login-user",)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.post(
    "/articles",
    response_model=ArticleOut,
    status_code=status.HTTP_201_CREATED,
    tags=["articles"],
    summary="Create article",
    description="Створити нову статтю",
    responses={
        201: {"description": "Стаття успішно створена"},
        401: {"description": "Потрібнф автентенфікація"},
    },
    operation_id="create-article",
    name="create-article"
)
def create_article(article: ArticleCreate, db: Session = Depends(get_db),
                   current_user: User = Depends(get_current_user)):
    tags_str = ",".join(article.tags)
    new_article = Article(
        title=article.title,
        content=article.content,
        tags=tags_str,
        author_id=current_user.id
    )
    db.add(new_article)
    db.commit()
    db.refresh(new_article)
    article_out = ArticleOut(
        title=new_article.title,
        content=new_article.content,
        tags=article.tags,
        author_id=new_article.id
    )
    return article_out


@app.get(
    "/articles",
    response_model=List[ArticleOut],
    status_code=status.HTTP_200_OK,
    tags=["articles"],
    summary="Get articles",
    description="Отримати список статей",
    responses={
        200: {"description": "Список статей повернуто"},
        401: {"description": "Потрібна автентифікація"},
    },
    operation_id="get-articles",
    name="get-articles"
)
def get_articles(skip: int = 0, limit: int = 10, db: Session = Depends(get_db),
                 current_user: User = Depends(get_current_user)):
    articles = db.query(Article).offset(skip).limit(limit).all()
    result = []
    for article in articles:
        result.append(ArticleOut(
            id=article.id,
            title=article.title,
            content=article.content,
            tags=article.tags.split(",") if article.tags else [],
            author_id=article.author_id
        ))
    return result


@app.get(
    "/",
    status_code=status.HTTP_200_OK,
    tags=["root"],
    summary="Головна сторінка",
    description="Повертає привітальне повідомлення",
    responses={
        200: {"description": "Успішна"},
    }
)
def read_root():
    return {"message": "Ласкаво просимо до InfoHub!"}
