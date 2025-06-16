# auth/jwks.py
import json
from pathlib import Path

from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiExample
from jwcrypto import jwk
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response

from auth.serializers import JWKSResponseSerializer


@extend_schema(
    summary="JSON Web Key Set Discovery",
    description=(
        "Provides the JSON Web Key Set (JWKS) containing the RSA public key(s) "
        "used by this service to sign JWTs.  \n\n"
        "Clients can fetch this document to dynamically verify tokens without "
        "having to bundle a static key."
    ),
    responses={
        200: OpenApiResponse(
            response=JWKSResponseSerializer,
            description="A standard JWKS document as per RFC7517.",
            examples=[
                OpenApiExample(
                    "example-jwks",
                    summary="Typical JWKS response",
                    value={
                        "keys": [
                            {
                                "kty": "RSA",
                                "use": "sig",
                                "alg": "RS256",
                                "kid": "2025-04-01-main-key",
                                "n": "oahUIop...base64url...",
                                "e": "AQAB"
                            }
                        ]
                    },
                )
            ],
        )
    },
    tags=["Authentication"],
)

class JWKSView(APIView):
    authentication_classes = []
    permission_classes     = []

    def get(self, request):
        pub_pem = Path(settings.JWT_PUBLIC_KEY_PATH).read_bytes()
        jwk_key = jwk.JWK.from_pem(pub_pem)
        jwk_dict = json.loads(jwk_key.export_public())
        return Response({"keys": [jwk_dict]})
