"""CatalogIQ — outbound mail via Amazon SES (SigV4, stdlib only).

Pattern ported from this lane's proven C4 sender: signed headers computed in
memory, POST to the SES endpoint. When AWS credentials are absent (local dev),
send() records to the console log and returns a stub id — the app NEVER blocks
on mail (SES is notification only, never the source of truth).
"""
import os, hashlib, hmac, urllib.request, urllib.parse
from datetime import datetime, timezone

REGION = os.environ.get("AWS_REGION", "us-east-2")
FROM = os.environ.get("MAIL_FROM", "CatalogIQ <info@catalogiqhq.com>")


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _key(secret, date, region, service):
    k = _sign(("AWS4" + secret).encode(), date)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def send(to: str, subject: str, body: str) -> tuple[bool, str]:
    ak = os.environ.get("AWS_ACCESS_KEY_ID", "")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    if not ak or not sk:
        print(f"[mailer:stub] to={to} subject={subject!r}")
        if os.environ.get("MAIL_DEBUG"):
            print(f"[mailer:stub-body] {body}")
        return True, "stub-no-creds"
    host = f"email.{REGION}.amazonaws.com"
    params = {
        "Action": "SendEmail", "Version": "2010-12-01",
        "Source": FROM, "Destination.ToAddresses.member.1": to,
        "Message.Subject.Data": subject, "Message.Body.Text.Data": body,
    }
    payload = urllib.parse.urlencode(params)
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = f"{datestamp}/{REGION}/ses/aws4_request"
    headers = {"host": host, "x-amz-date": amzdate}
    signed = ";".join(headers.keys())
    canon = ("POST\n/\n\n" + "".join(f"{k}:{v}\n" for k, v in headers.items())
             + "\n" + signed + "\n" + hashlib.sha256(payload.encode()).hexdigest())
    to_sign = ("AWS4-HMAC-SHA256\n" + amzdate + "\n" + scope + "\n"
               + hashlib.sha256(canon.encode()).hexdigest())
    sig = hmac.new(_key(sk, datestamp, REGION, "ses"),
                   to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
            f"SignedHeaders={signed}, Signature={sig}")
    req = urllib.request.Request(f"https://{host}/", data=payload.encode(),
                                 method="POST")
    req.add_header("Authorization", auth)
    req.add_header("X-Amz-Date", amzdate)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode()
        import re
        m = re.search(r"<MessageId>([^<]+)</MessageId>", text)
        return True, (m.group(1) if m else "sent")
    except Exception as e:
        print(f"[mailer:error] {e}")
        return False, str(e)
