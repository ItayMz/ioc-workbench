from fastapi import FastAPI

from app.routes.parse import router as parse_router

app = FastAPI(title="TSOC IOC Automation Portal")
app.include_router(parse_router)

@app.get("/")
def health_check():
    return {"status": "ok", "message": "IOC Automation backend is running"}