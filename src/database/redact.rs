//! Rendering a database URL without the password in it.
//!
//! A SQLite URL is a path and carries nothing worth hiding, which is why this
//! did not matter while SQLite was the only backend that worked. It is the
//! `migrate` subcommand that changes the arithmetic: it exists for Postgres and
//! MySQL, whose URLs carry credentials by construction, and it is run by hand
//! and from deploy pipelines whose logs outlive the terminal.
//!
//! Two places used to print the URL verbatim — the configuration banner every
//! command opens with, and the context on a failed connection, which is
//! precisely the case an operator pastes into a chat window when asking why the
//! deploy will not come up.

/// What stands in for the password. Deliberately not the same length as the
/// original: a redaction that preserves the length leaks the length.
const REDACTED: &str = "***";

/// A database URL with its password replaced by [`REDACTED`].
///
/// The username survives — it is what tells an operator which role failed to
/// authenticate, and it is not the secret. Anything that does not parse as
/// `scheme://[user[:password]@]host…` is returned unchanged, which covers
/// `sqlite://…` and every malformed URL: there is no password to find, so
/// there is nothing to hide.
///
/// A `password=` query parameter is redacted too. `sqlx` accepts one, so a URL
/// with an empty userinfo can still be carrying the secret.
pub fn redact_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };

    // The authority ends at the first delimiter that starts the path, query or
    // fragment. Splitting here first is what keeps an `@` in a path — or a
    // `password=` that is really part of a database name — out of the way.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);

    // The *last* `@` delimits the userinfo: a password must be percent-encoded
    // in a URL, so any `@` before it belongs to the userinfo rather than to the
    // host. The *first* `:` inside that userinfo delimits the password, for the
    // same reason in reverse — a colon in a username would have to be encoded.
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, _password)) => format!("{user}:{REDACTED}@{host}"),
            None => authority.to_string(),
        },
        None => authority.to_string(),
    };

    format!("{scheme}://{authority}{}", redact_query(tail))
}

/// Replace the value of any `password` parameter in the query string.
fn redact_query(tail: &str) -> String {
    let Some((path, query)) = tail.split_once('?') else {
        return tail.to_string();
    };

    // The fragment is not part of the query and must not be swept into the last
    // parameter's value.
    let (query, fragment) = match query.split_once('#') {
        Some((query, fragment)) => (query, Some(fragment)),
        None => (query, None),
    };

    let redacted = query
        .split('&')
        .map(|parameter| match parameter.split_once('=') {
            Some((name, _)) if name.eq_ignore_ascii_case("password") => {
                format!("{name}={REDACTED}")
            }
            _ => parameter.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");

    match fragment {
        Some(fragment) => format!("{path}?{redacted}#{fragment}"),
        None => format!("{path}?{redacted}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_postgres_password_is_replaced_and_the_user_kept() {
        assert_eq!(
            redact_credentials("postgres://kontor:hunter2@db.example.com:5432/kontor"),
            "postgres://kontor:***@db.example.com:5432/kontor"
        );
    }

    #[test]
    fn a_mysql_password_is_replaced() {
        assert_eq!(
            redact_credentials("mysql://root:hunter2@127.0.0.1:3306/kontor"),
            "mysql://root:***@127.0.0.1:3306/kontor"
        );
    }

    /// The whole point: a SQLite URL is a path, and mangling it would make the
    /// banner lie about where the database is for every node that runs one.
    #[test]
    fn a_sqlite_path_is_untouched() {
        for url in [
            "sqlite:///var/lib/kontor/storage.db?mode=rwc",
            "sqlite://./storage.db",
            "sqlite::memory:",
        ] {
            assert_eq!(redact_credentials(url), url);
        }
    }

    #[test]
    fn a_url_with_no_credentials_is_untouched() {
        assert_eq!(
            redact_credentials("postgres://db.example.com:5432/kontor"),
            "postgres://db.example.com:5432/kontor"
        );
    }

    /// A username on its own is not a secret, and blanking it would cost the
    /// one detail that says which role was rejected.
    #[test]
    fn a_username_without_a_password_survives() {
        assert_eq!(
            redact_credentials("postgres://kontor@db.example.com/kontor"),
            "postgres://kontor@db.example.com/kontor"
        );
    }

    /// `@` is legal in a percent-encoded password, so the split has to be on
    /// the last one. Splitting on the first would leave the tail of the
    /// password in the output, which is the failure that matters.
    #[test]
    fn an_at_sign_inside_the_password_does_not_split_early() {
        assert_eq!(
            redact_credentials("postgres://kontor:pa%40ss@db.example.com/kontor"),
            "postgres://kontor:***@db.example.com/kontor"
        );
    }

    /// An `@` in the *path* is not a userinfo delimiter, and treating it as one
    /// would invent a password and redact part of the database name.
    #[test]
    fn an_at_sign_in_the_path_is_not_a_delimiter() {
        assert_eq!(
            redact_credentials("postgres://db.example.com/kontor@shard1"),
            "postgres://db.example.com/kontor@shard1"
        );
    }

    #[test]
    fn a_password_query_parameter_is_replaced() {
        assert_eq!(
            redact_credentials(
                "mysql://root@127.0.0.1:3306/kontor?password=hunter2&ssl-mode=required"
            ),
            "mysql://root@127.0.0.1:3306/kontor?password=***&ssl-mode=required"
        );
    }

    /// Both halves at once, and the parameter name matched without regard to
    /// case — `sqlx` does not care either.
    #[test]
    fn userinfo_and_query_are_both_redacted() {
        assert_eq!(
            redact_credentials("mysql://root:hunter2@127.0.0.1/kontor?Password=hunter2#frag"),
            "mysql://root:***@127.0.0.1/kontor?Password=***#frag"
        );
    }

    /// Anything that is not a URL at all comes back as it went in, rather than
    /// being half-rewritten into something an operator cannot recognise.
    #[test]
    fn a_string_that_is_not_a_url_is_untouched() {
        for url in ["", "not a url", "postgres:/missing-slash"] {
            assert_eq!(redact_credentials(url), url);
        }
    }
}
