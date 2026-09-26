# Cladeon for Claude

**Which branch is your model actually on?**

When an AI vendor says "we trained our own model", Cladeon checks whether the files
they supply are consistent with that claim. It catches the common gap between the
pitch and the artifacts: a LoRA adapter on somebody else's base model, or a wrapper
around a hosted API.

This plugin teaches Claude to run Cladeon for you, show you what it will read before
it reads anything, and explain the result in plain language without overstating it.

## What it is, and what it is not

Cladeon is a **consistency screen**. It is not a lie detector, not a certification, and
not proof of what runs in production. Its most common correct answer is "not enough
evidence here", and the plugin tells Claude to say that plainly rather than turn it
into a pass or an accusation.

No detection rate is claimed. The scoring thresholds are uncalibrated and no blinded
benchmark has been run yet.

## Requirements

This plugin contains instructions only, no programs. You need the Cladeon
command-line tools (`cladeon-screen-cli` and `cladeon-verify`) installed on your
PATH. Download them from the
[Releases page](https://github.com/yigityucedag-ship-it/cladeon/releases), or
build them from source with `cargo build --release`.

## What it runs, sends and stores

- **Runs:** `cladeon-screen-cli` (preflight and scan) and `cladeon-verify` (check),
  on folders and files you name.
- **Sends:** nothing. Cladeon opens no network connection, and a test in its source
  enforces that. It never executes or deserialises the files it scans.
- **Stores:** one `.clade` bundle, written to the output folder you choose. Absolute
  paths, user names and credentials are removed before anything enters the bundle.
- **Your conversation:** Claude reads the text Cladeon prints, such as file counts,
  statuses and the vendor claim, and that text becomes part of your Claude
  conversation like anything else you share. Claude does not open the model files.

## Privacy Policy

The plugin collects no data. Cladeon runs entirely on your machine, sends nothing to
the author or to any third party, and keeps nothing except the bundle you ask it to
write, for as long as you keep it. Questions: open an issue on the GitHub repository.

## License

FSL-1.1-Apache-2.0: free to use, including inside your company. You may not offer it
as a competing paid product or service. Each release converts to Apache-2.0 two years
after it is published. See `LICENSE.md`.
