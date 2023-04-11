from django.middleware.csrf import CsrfViewMiddleware, RejectRequest, REASON_BAD_ORIGIN
from user_agents import parse


class CustomizedCsrfViewMiddleware(CsrfViewMiddleware):
    def process_view(self, request, callback, callback_args, callback_kwargs):
        parsed_user_agent = parse(request.META.get("HTTP_USER_AGENT"))
        is_mobile = parsed_user_agent.is_mobile
        is_pc = parsed_user_agent.is_pc  # accept csrftoken while coding to finish work faster

        if "Postman" or "curl" in request.META.get("HTTP_USER_AGENT"):
            print("It's a Postman or Curl, CSRFToken is ignored, Accepting request ...")
            return self._accept(request)

        if is_mobile:
            print("It's a mobile application, CSRFToken is ignored, Accepting request ...")
            return self._accept(request)

        if getattr(request, "csrf_processing_done", False):
            return None

        if getattr(callback, "csrf_exempt", False):
            return None

        if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
            return self._accept(request)

        if getattr(request, "_dont_enforce_csrf_checks", False):
            return self._accept(request)

        if "HTTP_ORIGIN" in request.META:
            if not self._origin_verified(request):
                return self._reject(
                    request, REASON_BAD_ORIGIN % request.META["HTTP_ORIGIN"]
                )
        elif request.is_secure():
            try:
                self._check_referer(request)
            except RejectRequest as exc:
                return self._reject(request, exc.reason)

        try:
            self._check_token(request)
        except RejectRequest as exc:
            return self._reject(request, exc.reason)

        return self._accept(request)
