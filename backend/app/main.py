from fastapi import FastAPI

app = FastAPI(title="TSOC IOC Automation Portal")

@app.get("/")
def health_check():
    return {"status": "ok", "message": "IOC Automation backend is running"}