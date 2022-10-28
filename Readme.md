# Fast-dualis-notifier
This is a faster implementation of [mflotos Dualis Notifier](https://github.com/mfloto/dualis-notifier).
All credits go to him, i've just made it faster.

## How to use
1. Clone this repo
2. Install [Rust](https://rustup.rs)
3. Configure your password in src/pass.txt, your username in src/user.txt and your webhook url in src/webhook.txt.
4. Run `cargo install cargo-lambda`
5. Run `cargo lambda build --release --output-format zip` and deploy to AWS lamdba.
(Or rip out the AWS stuff and run it locally)

