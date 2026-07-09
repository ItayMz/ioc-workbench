from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes.parse import router as parse_router

app = FastAPI(title="TSOC IOC Automation Portal")
app.include_router(parse_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "ok", "message": "IOC Automation backend is running"}