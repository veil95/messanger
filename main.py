from fastapi import FastAPI
from views.auth import router
from views.token_routes import token_router


app = FastAPI()

app.include_router(router)
app.include_router(token_router)

@app.get("/")
async def root():
    return {"message": "server work"}



