import time
from fastapi import FastAPI, HTTPException, status
from views.auth import router


app = FastAPI()

app.include_router(router)
@app.get("/")
async def root():
    return {"message": "server work"}



