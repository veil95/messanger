from fastapi import HTTPException, APIRouter, Response, Request
from controllers.jwt_handler import verify_refresh_token, create_refresh_token, create_access_token
from model.user import user_instance as user

token_router = APIRouter(prefix="/auth", tags=["token"])

@token_router.post("/refresh")
async def refresh_token(request: Request, response: Response) -> dict:
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found")

    payload = verify_refresh_token(refresh_token)

    user_data = user.get_user(payload.get("username"))

    new_access_token = create_access_token(user_data.get("username"))
    new_refresh_token = create_refresh_token(user_data.get("username"))

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=False,
        secure=True
    )

    return {"access_token": new_access_token, "type": "Bearer"}