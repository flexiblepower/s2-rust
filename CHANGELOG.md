# 0.2.0
- BREAKING: Reworked the way reception statuses are handled: instead of automatically confirming reception of messages, calling `receive_message` now returns an `UnconfirmedMessage` that the user can use to validate the message contents and send back the appropriate reception status.
- BREAKING: Replaced the constructors for most S2 types with builders. Constructors with one parameter have been left in place. This is done because the automatically generated constructors are pretty clunky, due to the frequent presence of optional fields. Builders are a little more verbose, but match the structure of most types better.

# 0.1.1
- No breaking changes.
- Documentation: minor formatting and typo corrections.
- Fixed a bug where `S2Connection::receive_message` would not return a `S2ConnectionError::ReceivedBadReceptionStatus` upon reception of a non-OK reception status in some circumstances.

# 0.1.0
The first release!