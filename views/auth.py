from fastapi import APIRouter, HTTPException, status
from controllers.user_auth import AuthController
from controllers.check_rate_limit import Ratelimit
from model.Token import create_access_token
from model.user import User, UserLogin, UserRequestRegistation
from model.user import user_instance as user

ratelimit = Ratelimit()
auth_controller = AuthController()

router = APIRouter(prefix="/auth", tags=["authentication"])

@router.post("/login")
async def login(user_data: UserLogin):
    print(user.users_db)
    ratelimit.increment_login_attempt(user_data.username)
    print(user.user_exists(user_data.username))
    print(auth_controller.verify_password(user_data.password, user.get_hashed_password(user_data.username)))
    if not (user.user_exists(user_data.username) or not
    (auth_controller.verify_password(user_data.password, user.get_hashed_password(user_data.username)))):
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Incorrect login or password"
        )

    if not ratelimit.check_rate_limit(user_data.username):
        raise HTTPException(
            status_code = status.HTTP_429_TOO_MANY_REQUESTS,
            detail = "Too many login attempts. Please try again later"
        )


    access_token = create_access_token(user_data.username)

    ratelimit.reset_attempts(user_data.username)

    return {"access_token": access_token, "type": "bearer"}


@router.post("/register")
async def register(user_data: UserRequestRegistation):
    if user.user_exists(user_data.username):
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "username is already registered"
        )
    if not auth_controller.check_password_len(user_data.password_plaintext):
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "your password is too easy, password must be at least 5 characters long"
        )
    if not auth_controller.check_username_len(user_data.username):
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail = "username must be at least 3 characters long"
        )

    hashed_password = auth_controller.hash_password(user_data.password_plaintext)

    user.create_user(user_data.username, hashed_password, user_data.displayname)

    return {f"message": "пользователь создан"}
