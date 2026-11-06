# Shells and Payloads

## Anatomy of a Shell

- Every operating system uses a *terminal emulator* to allow us to interact with a shell. Below is a table of common terminal emulators:

| Terminal Emulator | Operating System |
| --- | --- |
| Windows Terminal | Windows |
| cmder | Windows |
| PuTTY | Windows |
| kitty | Windows, Linux, macOS |
| Alacritty | Windows, Linux, macOS |
| xterm | Linux |
| GNOME Terminal | Linux |
| MATE Terminal | Linux |
| Konsole | Linux |
| Terminal | macOS |
| iTerm2 | macOS |


- Command Language Interpreter: It converts the user command into an operating system instruction in real time.


### Example

In the HTB Pwnbox, we can click the green icon to open the `MATE` terminal emulator.

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/115/green-square.png)

### Exercises

> Just use the commands in the questions.


## Bind Shells

- Definition: A shell where the target has the listener running and the attacker connects to it.

![Image Not Found](https://cdn.services-k8s.prod.aws.htb.systems/content/modules/115/bindshell.png)

- Challenges with a bindshell:
    - There needs to be an existing listener for this to work
    - Admins typically configure very strict incoming firewall rules and NAT on the edge of the network. So we can usually only do this from the internal network.
    - OS firewalls won't allow connections that aren't associated with trusted network-based applications.
