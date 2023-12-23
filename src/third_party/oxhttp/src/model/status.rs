use std::borrow::Borrow;
use std::error::Error;
use std::fmt;
use std::ops::Deref;

/// An HTTP [status](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.codes).
///
/// ```
/// use oxhttp::model::Status;
///
/// assert_eq!(Status::OK, Status::try_from(200)?);
/// # Result::<_,Box<dyn std::error::Error>>::Ok(())
/// ```
#[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
pub struct Status(u16);

impl Status {
    /// Is the status [informational](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.1xx).
    #[inline]
    pub fn is_informational(&self) -> bool {
        (100..=199).contains(&self.0)
    }

    /// Is the status [successful](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.2xx).
    #[inline]
    pub fn is_successful(&self) -> bool {
        (200..=299).contains(&self.0)
    }

    /// Is the status [related to redirections](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.3xx).
    #[inline]
    pub fn is_redirection(&self) -> bool {
        (300..=399).contains(&self.0)
    }

    /// Is the status a [client error](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.4xx).
    #[inline]
    pub fn is_client_error(&self) -> bool {
        (400..=499).contains(&self.0)
    }

    /// Is the status [server error](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.5xx).
    #[inline]
    pub fn is_server_error(&self) -> bool {
        (500..=599).contains(&self.0)
    }

    /// [100 Continue](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.100)
    pub const CONTINUE: Self = Self(100);
    /// [101 Switching Protocols](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.101)
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    /// [200 OK](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.200)
    pub const OK: Self = Self(200);
    /// [201 Created](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.201)
    pub const CREATED: Self = Self(201);
    /// [202 Accepted](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.202)
    pub const ACCEPTED: Self = Self(202);
    /// [203 Non-Authoritative Information](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.203)
    pub const NON_AUTHORITATIVE_INFORMATION: Self = Self(203);
    /// [204 No Content](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.204)
    pub const NO_CONTENT: Self = Self(204);
    /// [205 Reset Content](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.205)
    pub const RESET_CONTENT: Self = Self(205);
    /// [206 Partial Content](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.206)
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// [300 Multiple Choices](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.300)
    pub const MULTIPLE_CHOICES: Self = Self(300);
    /// [301 Moved Permanently](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.301)
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// [302 Found](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.302)
    pub const FOUND: Self = Self(302);
    /// [303 See Other](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.303)
    pub const SEE_OTHER: Self = Self(303);
    /// [304 Not Modified](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.304)
    pub const NOT_MODIFIED: Self = Self(304);
    /// [305 Use Proxy](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.305)
    pub const USE_PROXY: Self = Self(305);
    /// [307 Temporary Redirect](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.307)
    pub const TEMPORARY_REDIRECT: Self = Self(307);
    /// [308 Permanent Redirect](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.308)
    pub const PERMANENT_REDIRECT: Self = Self(308);
    /// [400 Bad Request](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.400)
    pub const BAD_REQUEST: Self = Self(400);
    /// [401 Unauthorized](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.401)
    pub const UNAUTHORIZED: Self = Self(401);
    /// [402 Payment Required](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.402)
    pub const PAYMENT_REQUIRED: Self = Self(402);
    /// [403 Forbidden](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.403)
    pub const FORBIDDEN: Self = Self(403);
    /// [404 Not Found](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.404)
    pub const NOT_FOUND: Self = Self(404);
    /// [405 Method Not Allowed](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.405)
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// [406 Not Acceptable](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.406)
    pub const NOT_ACCEPTABLE: Self = Self(406);
    /// [407 Proxy Authentication Required](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.407)
    pub const PROXY_AUTHENTICATION_REQUIRED: Self = Self(407);
    /// [408 Request Timeout](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.408)
    pub const REQUEST_TIMEOUT: Self = Self(408);
    /// [409 Conflict](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.409)
    pub const CONFLICT: Self = Self(409);
    /// [410 Gone](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.410)
    pub const GONE: Self = Self(410);
    /// [411 Length Required](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.411)
    pub const LENGTH_REQUIRED: Self = Self(411);
    /// [412 Precondition Failed](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.412)
    pub const PRECONDITION_FAILED: Self = Self(412);
    /// [413 Content Too Large](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.413)
    pub const CONTENT_TOO_LARGE: Self = Self(413);
    /// [414 URI Too Long](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.414)
    pub const URI_TOO_LONG: Self = Self(414);
    /// [415 Unsupported Media Type](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.415)
    pub const UNSUPPORTED_MEDIA_TYPE: Self = Self(415);
    /// [416 Range Not Satisfiable](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.416)
    pub const RANGE_NOT_SATISFIABLE: Self = Self(416);
    /// [417 Expectation Failed](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.417)
    pub const EXPECTATION_FAILED: Self = Self(417);
    /// [421 Misdirected Request](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.421)
    pub const MISDIRECTED_REQUEST: Self = Self(421);
    /// [422 Unprocessable Content](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.422)
    pub const UNPROCESSABLE_CONTENT: Self = Self(422);
    /// [426 Upgrade Required](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.426)
    pub const UPGRADE_REQUIRED: Self = Self(426);
    /// [500 Internal Server Error](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.500)
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// [501 Not Implemented](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.501)
    pub const NOT_IMPLEMENTED: Self = Self(501);
    /// [502 Bad Gateway](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.502)
    pub const BAD_GATEWAY: Self = Self(502);
    /// [503 Service Unavailable](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.503)
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// [504 Gateway Timeout](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.504)
    pub const GATEWAY_TIMEOUT: Self = Self(504);
    /// [505 HTTP Version Not Supported](https://httpwg.org/http-core/draft-ietf-httpbis-semantics-latest.html#status.505)
    pub const HTTP_VERSION_NOT_SUPPORTED: Self = Self(505);

    pub(crate) fn reason_phrase(&self) -> Option<&'static str> {
        match self.0 {
            100 => Some("Continue"),
            101 => Some("Switching Protocols"),
            102 => Some("Processing"),
            103 => Some("Early Hints"),
            200 => Some("OK"),
            201 => Some("Created"),
            202 => Some("Accepted"),
            203 => Some("Non-Authoritative Information"),
            204 => Some("No Content"),
            205 => Some("Reset Content"),
            206 => Some("Partial Content"),
            207 => Some("Multi-Status"),
            208 => Some("Already Reported"),
            226 => Some("IM Used"),
            300 => Some("Multiple Choices"),
            301 => Some("Moved Permanently"),
            302 => Some("Found"),
            303 => Some("See Other"),
            304 => Some("Not Modified"),
            305 => Some("Use Proxy"),
            307 => Some("Temporary Redirect"),
            308 => Some("Permanent Redirect"),
            400 => Some("Bad Request"),
            401 => Some("Unauthorized"),
            402 => Some("Payment Required"),
            403 => Some("Forbidden"),
            404 => Some("Not Found"),
            405 => Some("Method Not Allowed"),
            406 => Some("Not Acceptable"),
            407 => Some("Proxy Authentication Required"),
            408 => Some("Request Timeout"),
            409 => Some("Conflict"),
            410 => Some("Gone"),
            411 => Some("Length Required"),
            412 => Some("Precondition Failed"),
            413 => Some("Content Too Large"),
            414 => Some("URI Too Long"),
            415 => Some("Unsupported Media Type"),
            416 => Some("Range Not Satisfiable"),
            417 => Some("Expectation Failed"),
            421 => Some("Misdirected Request"),
            422 => Some("Unprocessable Content"),
            423 => Some("Locked"),
            424 => Some("Failed Dependency"),
            425 => Some("Too Early"),
            426 => Some("Upgrade Required"),
            428 => Some("Precondition Required"),
            429 => Some("Too Many Requests"),
            431 => Some("Request Header Fields Too Large"),
            451 => Some("Unavailable For Legal Reasons"),
            500 => Some("Internal Server Error"),
            501 => Some("Not Implemented"),
            502 => Some("Bad Gateway"),
            503 => Some("Service Unavailable"),
            504 => Some("Gateway Timeout"),
            505 => Some("HTTP Version Not Supported"),
            506 => Some("Variant Also Negotiates"),
            507 => Some("Insufficient Storage"),
            508 => Some("Loop Detected"),
            510 => Some("Not Extended"),
            511 => Some("Network Authentication Required"),
            _ => None,
        }
    }
}

impl Deref for Status {
    type Target = u16;

    #[inline]
    fn deref(&self) -> &u16 {
        &self.0
    }
}

impl AsRef<u16> for Status {
    #[inline]
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl Borrow<u16> for Status {
    #[inline]
    fn borrow(&self) -> &u16 {
        &self.0
    }
}

impl TryFrom<u16> for Status {
    type Error = InvalidStatus;

    #[inline]
    fn try_from(code: u16) -> Result<Self, InvalidStatus> {
        if (0..=999).contains(&code) {
            Ok(Self(code))
        } else {
            Err(InvalidStatus(code))
        }
    }
}

impl From<Status> for u16 {
    #[inline]
    fn from(status: Status) -> Self {
        status.0
    }
}

impl fmt::Display for Status {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase().unwrap_or(""))
    }
}

/// Error returned by [`Status::try_from`].
#[allow(missing_copy_implementations)]
#[derive(Debug, Clone)]
pub struct InvalidStatus(u16);

impl fmt::Display for InvalidStatus {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The HTTP status code should be between 0 and 999, '{}' found",
            self.0
        )
    }
}

impl Error for InvalidStatus {}
