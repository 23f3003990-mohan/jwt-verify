import jwt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-zneq8m4u.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def invalid(reason: str):
    return JSONResponse({"valid": False, "error": reason}, status_code=401)


async def verify(request: Request):
    try:
        body = await request.json()
        token = body["token"]
        if not isinstance(token, str):
            raise TypeError
    except Exception:
        return invalid("request body must be JSON {\"token\": \"<JWT>\"}")
    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],            # only RS256: blocks alg=none / HS256 key-confusion
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        return invalid("token expired")
    except jwt.InvalidAudienceError:
        return invalid("wrong audience")
    except jwt.InvalidIssuerError:
        return invalid("wrong issuer")
    except jwt.InvalidSignatureError:
        return invalid("bad signature")
    except jwt.PyJWTError as e:
        return invalid(f"invalid token: {e.__class__.__name__}")
    return {"valid": True, "email": claims.get("email"), "sub": claims.get("sub"), "aud": claims.get("aud")}


@app.api_route("/{full_path:path}", methods=["GET", "POST"])
async def router(full_path: str, request: Request):
    # Match on the last path segment so it works whatever path Vercel forwards.
    if request.method == "POST":
        return await verify(request)
    return {"status": "ok", "usage": "POST /verify with {\"token\": \"<JWT>\"}", "seen_path": "/" + full_path}
