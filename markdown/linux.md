---
title: linux basics
description: a variety of linux topics for beginners
published_at: 2018-12-23
last_modified_at: 2018-12-23
---

# Linux basics

Become a sweet Linux h4ck3r or your money back, guaranteed.

## Core Features

### Where does the shell fit into the big picture?

A shell is just a normal program on your computer. Essentially, it follows this basic flow:

* Accept some text input from a user
* Process the user's input, doing things like looking up environment variables
* Print the text output back to the user

The middle step in the above list can become a bit complicated when we consider things like piping output from one command to another and command subsitution. It's important to remember, though, that shells are also just programs that follow a predefined and replicable set of steps which we can trace through ourselves.

While shell programs (`sh`, `bash`, and friends) live in user space (i.e., they execute separately from the internal workings of the OS), they can be used to perform low-level and high-level tasks alike. An example of a low-level task would be running some system initialization scripts (i.e., those in `/etc/init.d/`) on system startup. An example of a high-level task would be using the `find` program to search for files on your system.

Shell languages are usually a bit more clunky than your traditional programming languages (i.e., C and Python) for operations like arithmetic. Shells really shine in the following tasks:

* File system navigation
* Orchestrating the calling of other programs that handle more complicated tasks
* Text processing

In summary, you can think of shells as programs that make it easier for you to run other programs and process their results. They are the glue for piecing together the trove of powerful tools that come installed on a standard Linux distribution.

### Common shells

A very nice table comparing the features of the below shells can be found in [this Stackoverflow answer](https://stackoverflow.com/a/31801862/5094008).

#### Bourne Shell - `sh`

The grandpappy of them all. The oldest and least-feature-complete shell around. Lacks a lot of nice-to-have things like auto-completion, job control, and aliases. But, it's what the pilgrims used to found America, so there's certainly some nostalgia associated with it.

#### Bourne Again Shell - `bash`

`bash` is a superset of `sh`. Note that in some environments, the program referred to by `sh` actually points to an instance of the `bash` program.

`bash` added a lot of features to the underlying `sh` specification and is much nicer to work in. Pros over `sh` include:

* Job control
* Aliases
* A directory stack
* Command history
* Filename / username / hostname / history auto-completion
* Builtin arithmetic evaluation

#### Debian Almquist Shell - `dash`

An implementation of `sh`.

From an exploitation standpoint, `dash` can sometimes be a low-hanging fruit because it does not strip setuid privileges like some other more-modern shells do. But more on that later when we get to suid and sticky bits.

#### KornShell - `ksh`

Written by David G. Korn at AT&T Bell Laboratories, aiming to combine the best features of `bash` and `csh`. `ksh` is a larger program (in terms of raw size) than `bash` or `csh`, but boasts improved performance. Conforms to the IEEE Shell Language Standard.

#### C Shell - `csh`

A shell inspired by the C language. As such, this shell (and the derivative `tcsh` shell) stray from the traditional `sh`-based syntax. An example of `csh`'s different looping syntax is shown below.
```csh
#!/bin/csh
foreach number (one two three exit four)
  if ($number == exit) then
    echo reached an exit
    break
  endif
  echo $number
end
```

#### T C Shell - `tcsh`

Fun fact: the T in the name comes from the T in the [TENEX operating system](https://en.wikipedia.org/wiki/TOPS-20). Here is a pretty neat analogy that will hopeuflly demonstrate the relationship of `tcsh` to `csh`:

`tcsh` : `csh` :: `bash` : `sh`

For a comparison between the feature sets of `tcsh` and `csh`, see the table at [this link](https://web.fe.up.pt/~jmcruz/etc/unix/sh-vs-csh.html).

#### Z Shell - `zsh`

An extended version of the `bash` shell that also includes features from `ksh` and `tcsh`. The first version of `zsh` was written by Paul Falstad in 1990 while still a student at Princeton. Wowzers! Some interesting features that `zsh` has include spelling correction and improved variable/array handling.

#### ***SUPER IMPORTANT NOTE***

I myself am quite partial to the [fish shell](https://fishshell.com/), but that is not part of the course.

### Bash basics

#### Command prompt

There are a couple of environment variables that you can configure to contorl the prompt you see in a Bash session: `PS1` and `PS2`. The `PS1` variable controls the top-level prompt (i.e., the one you see when you first enter a Bash session). Here's a quick example:
```sh
$ export PS1="brian rocks>"
brian rocks>
```

The `PS2` variable controls the secondary prompt (i.e., the one that appears when you continue onto a newline within a single command). Here's a quick example:
```sh
$ export PS2="brian rocks on the 2nd level, too>"
$ echo <<EOF
brian rocks on the 2nd level, too>
```

There's also a variety of variables you can use within your definitions of `PS1` and `PS2`, which you can find out more about [here](https://www.cyberciti.biz/tips/howto-linux-unix-bash-shell-setup-prompt.html).

#### Piping between commands

For a simple explanation, checkout [this Stackoverflow answer](https://stackoverflow.com/questions/9834086/what-is-a-simple-explanation-for-how-pipes-work-in-bash)

A Unix pipe is really quite simple. It connects the stdout fle descriptor of the first process in the pipeline to the stdin file descriptor of the second process. So, when the first process writes to its stdout, that ouptut becomes immediately available on the stdin of the second process.

It's important to note that two processes that you are connecting via a pipe (`|`) are started *in parallel*. Here's a simple example demonstrating this:
```sh
$ ps | cat
   PID TTY          TIME CMD
  2532 pts/0    00:00:00 bash
  2641 pts/0    00:00:00 ps
  2642 pts/0    00:00:00 cat
```

If these commands were not run as concurrent processes, then `cat` would not appear as an active process in the output for `ps`.

#### Named pipes

Named pipes (also known as FIFOs due to their first-in-first-out behavior) are an extension to the unnamed, unidirectional pipes (`|`) we examined above. Named pipes are methods of inter-process communication (IPC). [The Wikipedia page](https://en.wikipedia.org/wiki/Named_pipe) provides a good overview of them, but we'll take a closer look below.

Named pipes can be created using either `mkfifo` or `mknod`. While both of these are part of the POSIX standard, `mkfifo` provides a simpler interface to `mknod` and is the preferred method of creating named pipes. [This Stackoverflow answer](https://stackoverflow.com/questions/43023329/difference-between-mkfifo-and-mknod) breaks it down nicely.

One relevant application for named pipes is creating simple Netcat proxies. Here's a quick and dirty example:
```sh
$ mkfifo proxypipe
$ nc -lvp 4444 0<proxypipe | nc www.google.com 80 1>proxypipe
```

What's going on here? We kick things off by creating a named pipe, named `proxypipe`. This is the channel over which our two Netcat (`nc`) commands will talk to each other on the next line.

On this next line, we first setup a Netcat listener on port `4444`. You can see that we redirect our `proxypipe` named pipe into file descriptor 0 of this Netcat process (which is its standard in).

Finally, on the right side of the second line in our example, we open a connection to Google (via the HTTP default port 80). We forward all data received from this process's stdout (file descriptor 1) into our named `proxypipe` pipe.

When all of this is combined, we are able to send traffic to port `4444` on our local host, which gets forwarded to Google. Anything received from the connection to Google is then passed back to our local Netcat listener on port `4444`. Note that this example would not worked quite the same with an unnamed pipe, as we rely on the bidirectional nature of named pipes to pass data back-and-forth over our simple proxy.

Named pipes will appear as files when navigating your file system, and you can remove them via `rm` when you're done with them, just like regular files.

#### I/O redirection

A comprehensive reference can be found [here](https://www.tldp.org/LDP/abs/html/io-redirection.html), but we will look into the highlights below.

We've already seen I/O redirection in some of our earlier examples, so we will just touch on some of the major items below. Output redirection allows us to send the output of a command to another destination. Here's a really simple example that just takes the output of a command and writes it to a file:
```sh
$ ls > ls.txt
```

This is nice, but here's a much more practical example of using this simple redirection to play an MP3 file:
```sh
$ cat screamingturtles.mp3 > /dev/audio
```

The above examples have just been redirecting the stdout streams of processes. We can also redirect the stderr stream via its file descriptor `2`. This is useful for omitting errors from our output:
```sh
find / -name secrets.txt 2>/dev/null
```

Following this example, we can merge our stderr and stdout streams so that they are written to the same location.
```sh
echo writing both stdout and stderr to a file > file.txt 2>&1
```

However, a much simpler alternative to achieve the same is:
```sh
echo writing both streams to a file &> file.txt
```

We can also redirect input. The single `<` operator can be used to write the contents of a file on a process's stdin stream. Of note is that we can also redirect command output as input using a variation of the `<` operator. Here's a quick look:
```sh
$ cat < <(echo "check this out")
check this out
```

Something even cooler is the here document (`<<`), which is a method for appending input until a certain sequence is read. Here's an a example showing how you could write a Bash script within a Bash session:
```sh
$ bash <<EOF
> #!/usr/bin/env bash
> echo This inlined script is Bash-ception!
> EOF
This inlined script is Bash-ception!
```

Something ***EVEN COOLER*** is the here string (`<<<`). This allows you to send write a string onto the input stream of a process. Take a look:
```sh
$ base64 -d <<< TG9seiBjYW4ndCBiZWxpZXZlIHlvdSBsb29rZWQgYXQgdGhpcwo=
```

#### Arithmetic

Arithmetic in Bash is pretty simple. Contrary to what certain instructors like to teach, there are actually a few different ways to perform arithmetic in Bash. Let's take a look at the first: enclosing your expressions in a `$(( ))` block. Here's a quick example:
```sh
$ a=$((3 * 5))
$ echo $a
15
$ ((++a))
$ echo $a
16
```

Alternatively, Bash includes a built-in `let` statement that supports arithmetic operations. Let's take a look at some examples:
```sh
$ let a=5+4
$ echo $a
9
$ let "a = 5 / 4"
$ echo $a
1
$ echo $a
2
```

Yet another option for crunching numbers from the terminal is the `expr` program. Note that this is not a Bash built-in like the two previous methods, and is consquently a bit more powerful. This program does not require enclosing your expressions in quotes and will print your result to stdout. Let's take a look:
```sh
$ expr 1 + 2
3
$ b=`expr 10 * 2`
$ echo $b
20
$ a=`expr $b - 5`
$ echo $a
15
```

While not directly related to arithmetic, it may be useful to sometimes determine the lenght of a string variable within your expressions. You can do so via the `${#var}` construct. Here's a simple example:
```sh
$ brian=wowthatguyiscool
$ echo ${#brian}
16
```

Just keep in mind that Bash should never really be your choice for any serious mathematical tasks. If you really need to compute math on the command-line, something like Python is probably your best bet:
```sh
$ python3 -c "print(2**8)"
256
```

### Bash / shell initialization

Each time you run an instance of the `bash` program, it is started with a separate "context". What this means is that the environment in which `bash` executes your command or script will be different based on a variety of factors, including:

* Scripts that ran before it that modified the environment
* The user that ran the command or script
* Environment variables set in your operating system or Linux distribution
* Aliases set both globally and for your user

It simple terms, just think of the environment as the persistent information on your system that will affect the information that `bash` sees. In the wonderful world of `bash`, there is a predefined set of scripts that get automatically executed during different events.

You can check out a comprehensive reference of these scripts [here](https://linux.die.net/Bash-Beginners-Guide/sect_03_01.html), but we'll explore the highlights below. Note that the `~` character in the below file paths refers to the current user's home directory (i.e., `/home/brian`)

#### `/etc/profile`

This system-wide script is invoked for login shells and sets variables like `PATH`, `USER`, `MAIL`, `HOSTNAME`, and `HISTSIZE`. It is important to note that this file is used by shells other than `bash`.

#### `/etc/bashrc`

This system-wide script can be thought of similarly to `/etc/profile`, but is only run by the `bash` shell. Consequently, you tend to find more function definitions and `bash`-specific aliases in here. Here is a sample `pskill` function implementation that is commonly found in `/etc/bashrc`:
```sh
pskill()
{
    local pid
    pid=$(ps -ax | grep $1 | grep -v grep | gawk '{ print $1 }')
    echo -n "killing $1 (process $pid)..."
    kill -9 $pid
    echo "slaughtered."
}
```

#### `~/.bash_profile`

The preferred configuration file for configuring user environments individually.

#### `~/.bash_login`

Contains specific settings that are only executed when you first login to the system. You may do something like set the `umask` value in here.

#### `~/.profile`

A fallback in the absence of `~/.bash_login` and `~/.bash_profile`. Note that this may be used by other shells which cannot grok `bash` syntax.

#### `~/.bashrc`

This file is similar to `~/.bash_profile` in what should be included within it. However, an important distinction is that your `~/.bashrc` will also be executed for non-login sessions.

#### `~/.bash_logout`

Contains specific instructions for a user's logout procedure. You might insert a `clear` command in your `~/.bash_logout`, in order to leave a clear terminal window when closing remote connections.

### Login versus non-login shells

For a nice explanation, see these StackExchange questions:

* [Difference between Login Shell and Non-Login Shell?](https://unix.stackexchange.com/questions/38175/difference-between-login-shell-and-non-login-shell).
* [What is the difference between interactive shells, login shells, non-login shell and their use cases?](https://unix.stackexchange.com/questions/50665/what-is-the-difference-between-interactive-shells-login-shells-non-login-shell)

A login shell is the first process that executes under your user ID when you login for an interactive session. An interactive session is one in which commands are run with keyboard interaction enabled. Non-interactive sessions are those that run without the expectation of any human interaction (something like an automated process that runs on the system periodically).

So, when you login to your computer via `ssh` or start a new session with `su -`, you are beginning an *interactive login* shell. When you start a shell in an existing session (i.e., running the `bash` command within an already-running terminal session), you are running an *interactive non-login* shell (which makes sense, because you didn't login to the computer when you opened this new `bash` session).

This distinction is important, because some initialization scripts will only run when a user first logs onto the system. But how can I know if I am in a login shell? I'm glad you asked.
```sh
# the leading dash in the below output indicates that this is a login shell
$ echo $0
-bash

# the lack of a leading dash in the below output indicates that this is not a login shell
$ echo $0
bash
```

Don't fall into the trap of thinking that you'll always initially be accessing a login shell, though. It is fairly common today to login to systems graphically via X terminal windows, in which case `bash` will begin as a non-login shell (as the terminal window manager will handle the user login).

### Modifying contexts with `set`, `export`, `env`, `exec`, and `eval`

The following resources provide a nice background:

* [What's the difference between set, export and env and when should I use each?](https://askubuntu.com/questions/205688/whats-the-difference-between-set-export-and-env-and-when-should-i-use-each)
* [What's the difference between eval and exec?](https://unix.stackexchange.com/questions/296838/whats-the-difference-between-eval-and-exec)

Let's start with looking at environment modifications with regard to `export`. When you set a variable without any specifiers, its definition does not persist beyond the current process. Here's a quick example:
```sh
$ brian=awesome
$ echo $brian
awesome
$ bash -c 'echo $brian'

```

Note that it is also a common pattern to set variables on the same line as a command invocation, so that these variable definitions will be passed to the child process spawned for that command. Here's a quick example:
```sh
$ brian=awesome bash -c 'echo $brian'
awesome
$ bash -c 'echo $brian'

```

However, when you use `export`, defined variables *will* persist to child processes. It's important to remember that each time you enter a command in a Bash shell, that command is running as a spawned child process. Here's a simple example, following the patterns from above:
```sh
$ export brian=awesome
$ bash -c 'echo $brian'
awesome
```

Note that these `export`-ed variables don't persist after your Bash parent process gets terminated. If you want some variables to always be available to you, `export` them via statements in your `~/.bashrc`. If you want to "un-set" an `export`-ed variable, you can do just that with `unset`.

Let's throw `env` into the mix. `env`, as opposed to the Bash built-ins we've looked at thus far, is an external program. This means that there is an actual `/usr/bin/env` binary that exists on your system. Consequently, `env` is completely unaware of Bash concepts like shell variables (not to be confused with *environment* variables) and aliases.

One common application of the `env` program is to invoke another program, with all Bash environment clutter like aliases stripped out. This can be done pretty simply:
```sh
$ env ./myprogram
```

You can also use `env` to define variables that will be included in the context in which the specified command runs. Here's a simple example:
```sh
$ env MY_VARIABLE=eleventyhundred ./myprogram
```

Another good time to use `env` is in the [shebang](https://en.wikipedia.org/wiki/Shebang_(Unix)) lines in your scripts. For example, this:
```python
#!/usr/bin/env python3
print('hey there, qt pi')
```

Is superior to:
```python
#!/usr/bin/python3
print('hey there, qt pi')
```

In the event that the user running this Python 3 script has redefined where `python3` points to in their current environment. This also avoids issues stemming from the fact that many Linux distributions have a separate location for the `python`/`python3` binaries but, for the most part, they all agree that `env` belongs in `/usr/bin`.

We also have the Bash built-in of `set`. For starters, know that just entering the `set` command without arguments is a nice way to dump our entire environment, including environment variables, shell variables, and function definitions. This is in contrast to the empty `env` command, which only displays environment variables.

`set`, as opposed to `env`, can be used for setting shell variables (which includes the implicit positional arguments `$1`, `$2`, and so on). Here's a quick example:
```sh
$ set brian=awesome
$ echo "$1"
brian=awesome
```

Let's next dive in to `exec` and `eval`. While these two commands may seem similar in the fact that they can be used to execute commands, they are actually quite different when you examine them in detail.

Executing the command `exec ./myprogram` is actually quite similar to running `./myprogram` within Bash. The key difference is that the `exec` version actually replaces your current Bash process with that of the specified command (via `fork()`). The `exec`-less version spawns a child process from the Bash parent process. Here's an example showing how running a command with `exec` preserves the PID of the parent Bash process:
```sh
$ bash -c 'echo $$; ls -l /proc/self'
30726
lrwxrwxrwx 1 root root 0 Dec 11 16:35 /proc/self -> 30727
$ bash -c 'echo $$; exec ls -l /proc/self'
30728
lrwxrwxrwx 1 root root 0 Dec 11 16:35 /proc/self -> 30728
```

`eval`, on the other hand, will run the specified arguments as a command within the current shell. The important piece here is that variables will be expanded *before* executing. Here's a simple example demonstrating this:
```sh
$ cmd='brian=awesome'
$ echo $brian

$ eval $cmd
$ echo $brian
awesome
```

### File system hierarchy

There's a standard for that: [Filesystem Hierarchy Standard](https://en.wikipedia.org/wiki/Filesystem_Hierarchy_Standard). Here are some of the common directories included on most (if not all) mainstream Linux distros:

* `/` - the root directory of the entire file system
* `/bin` - essential command binaries that *must* be available in single user mode
* `/boot` - boot loader files
* `/dev` - device drivers that appear in the file system as if they were ordinary files
  * `/dev/null` - accepts all data written to it without storing it
  * `/dev/random` - random number generator that blocks when it runs out of entropy
  * `/dev/urandom` - random number generator that will *never* block (just like the Minnesota Vikings offensive line @BigMike)
  * `/dev/shm` - a temporary file storage file system (i.e., `tmpfs`) that uses RAM for the backing store
* `/etc` - host-specific sytem-wide configuration files
* `/home` - users' home directories
* `/lib` - shared libraries essential for the operation of programs in `/bin` and `/sbin`
* `/media` - mount points for removable media such as CD-ROMs
* `/mnt` - temporarily-mounted file systems
* `/opt` - optional application software packages (an artifact from when AT&T used to sell additional software operations with their Unix distro)
* `/proc` - virtual file system providing process and kernel information as files
* `/root` - home directory for the `root` user
* `/sbin` - essential system binaries
* `/srv` - site-specific data served by this system (see also: `var/www/html`)
* `/sys` - contains information about devices, drivers, and some kernel features
* `/tmp` - temporary files, which are often not preserved between system reboots
* `/usr` - secondary hierarchy for read-only user data, containing the majority of multi-user utilities and applications
  * `/usr/bin` - non-essential command binaries
  * `/usr/include` - standard include files
  * `/usr/lib` - libraries for the binaries in `/usr/bin` and `/usr/sbin`
  * `/usr/local` - tertiary hierarchy for local data, specific to this host
  * `/usr/sbin` - non-essential system binaries (such as daemons for various network services)
  * `/usr/share` - architecture-independent shared data
  * `/usr/src` - source code (you might find the kernel source here)
* `/var` - variable files (i.e., files whose contents should be expected to change over the course of system operation)
  * `/var/cache` - application cache data
  * `/var/lib` - state information (i.e., persistent data modified by programs as they run)
  * `/var/lock` - lock files, for keeping track of resources currently in use
  * `/var/log` - log files
  * `/var/mail` - mailbox files (replaces the deprecated `/var/spool/mail`)
  * `/var/opt` - variable data from add-on packages that are stored in `/opt`
  * `/var/run` - run-time variable data
  * `/var/spool` - spools for tasks waiting to be processed (i.e., print queues and the outgoing mail queue)
  * `/var/tmp` - temporary files to be preserved between reboots

### File permissions & attributes

Basic file permissions are pretty simple and have numerical and text representations. Here is a simple example of the text representation of a file's permissions:
```sh
$ ls -l /usr/bin/env
-rwxr-xr-x 1 root root 35000 Jan 18  2018 /usr/bin/env
```

There are also a few other permissions associated with files:

* Set User ID (SUID) - programs set with SUID run under the secuirty context of the owner of the program
* Set Group ID (SGID) - programs set with SGID run under the security context of the group of the program
* Sticky bit - when set on a directory only the owner of the file can delete or rename files in the directory

File properties:

* `-` - regular file
* `d` - directory
* `l` - link (symbolic or hard)
* `b` - block special file
* `c` - character special file
* `s` - socket
* `p` - named pipe (`mknod`, `mkfifo`, etc.)

All of these file permissions also have a numeric representation, summarized in the following table.

| Permission | Number |
| ---------- | ------ |
| Read | 4 |
| Write | 2 |
| Execute | 1 |
| Set User ID | 4 |
| Set Group ID | 2 |
| Sticky bit | 1 |

Using the numeric values from this table, we can create octal groupings of permissions to provide an alternative representation. These octal groupings are four-digit numbers, with each number representing the sum of the number values for the special, user, group, and other permissions, respectively.

We can modify file permissions and ownership with the `chmod`, `chown`, and `chgrp` commands.

There are also some file attributes that deal with timetstamps. On `ext3`, we have:

* `mtime` - the time the file was last modified
* `atime` - the time the file was last accessed (persistent for 24 hours)
* `ctime` - time of inode record change (file attribute changes: size, location, type, etc.)

On `ext4`, we also have:

* `crtime` - creation time

[Extended file attributes](https://en.wikipedia.org/wiki/Extended_file_attributes) are file system features that enable users to associate files with metadata not interpreted by the file system. These act as name:value pairs associated permanently with files and directories in a manner similar to the environment strings associated with a process.

### Regular expressions

Regular expressions are a powerful way to search text for patterns. A powerful tool that provides a means for applying regular expressions to text is `grep`. Some important options for `grep` are:

* `-v` - remove lines matching the pattern
* `-E` - enable the extended regular expression syntax
* `-P` - use Perl-style regular expression syntax
* `-o` - display only the text that matches the regular expression
* `-i` - case insensitive search

Some basic regular expression syntax that is good to know:

* `^` - the beginning of a line
* `$` - the end of a line
* `[A-Z]` - specify a range of characters
* `{num}` - specify the number of matches from a group
* `\<`, `\>` - anchor a pattern to the start or end of a word, respectively
* `*` - match a group 0 or more times
* `+` - match a group 1 or more times
* `|` - OR operator for matching one of many patterns


## Boot Processes

### Boot flow

As usual, [the Wikipedia page](https://en.wikipedia.org/wiki/Linux_startup_process) is a good reference.

The basic flow is:

* BIOS / system start (system startup / hardware initialization)
* MBR loading (boot loader stage 1)
* GRUB boot loader (boot loader stage 2)
* Kernel (Linux OS)
* INIT process (run levels)
* User prompt (user commands)

The Master Boot Record consists of 512 bytes:

* Bootstrap code of 446 bytes
* Partition table of 64 bytes
* Boot signature (`0x55`, `0xAA`) of 2 bytes

### System V init versus `systemd`

System V init begins by running the `/sbin/init` program, which runs with PID 1. This program goes on to run `/etc/rc.d/rc.sysinit`, which in turn calls upon the corresponding `/etc/rc?.d` file (according to the specified runlevel). Here are the System V init runlevels:

* `0` - halt
* `1` - single-user text mode
* `2` - not used (user-definable)
* `3` - full multi-user text mode
* `4` - not used (user-definable)
* `5` - full multi-user graphical mode (with an X-based login screen)
* `6` - reboot

`systemd` refers to the name of the daemon process that runs with PID 1 in this alternative system for managing startup and services within a Linux OS. A key advantage of `systemd` is greatly improved parallelism. As opposed to runlevels, `systemd` uses *targets*. Here they are:

* `poweroff.target` - shut down and power off
* `resuce.target` - set up a rescue shell
* `multi-user.target` - set up a non-graphical multi-user shell
* `graphical.target` - set up a graphical multi-user shell
* `reboot.target` - shut down and reboot the system

Both of these systems have slightly different methods of controlling services. Here is a breakdown of some common operations:

| Goal | System V init | `systemd` |
| ---- | ------------- | --------- |
| Start a service | `service example start` | `systemctl start example` |
| Stop a service | `service example stop` | `systemctl stop example` |
| Restart a service | `service example restart` | `systemctl restart example` |
| Check a service's status | `service example status` | `systemctl status example` |


### Boot configuration files

The following files play an important role in the boot process:

* `/boot/map` - contains the location of the kernel
* `/boot/vmlinuz` / `/boot/vmlinuz-kernel-version` - the kernel or a symbolic link to the kernel
* `/boot/grub/device.map` - maps devices in `/dev` to those used by grub
* `/boot/grub/grub.conf` / `/boot/grub/menu.lst` - grub configuration file
* `/boot/grub/messages` - grub boot-up welcome messages
* `/boot/grub/splash.xpm.gz` - grup boot-up background image


## Scripts & Processes

### Scripting

While you may interact with Bash a lot on the command-line, Bash scripts are another powerful way of using this shell language. You can think of Bash scripts as a sequence of Bash commands that work together to complete some more-complicated task. You should always start your Bash scripts with the line `#!/usr/bin/env bash`, as this lets the shell to use Bash to execute this script.

I'm not going to go into scripting into very much detail. If you want to learn more, head on over to the [Advanced Bash-Scripting Guide](http://tldp.org/LDP/abs/html/).

One thing I will touch on is the special `$` variables available to you within your scripts. While these are also available from the command-line, I found myself using them more often within scripts. For a nice explanation of all of them, see [this Stackoverflow answer](https://stackoverflow.com/questions/5163144/what-are-the-special-dollar-sign-shell-variables).

Some of the most commonly-used of these variables are:

* `$0` - name of the shell or shell script
* `$$` - pid of the current shell
* `$-` - current options set for the shell
* `$?` - most recent foreground pipeline exit status
* `$!` - pid of the most recent background command
* `$IFS` - the input field separator

And here are some of the more important ones specifically for scripting:

* `$1`, `$2`, etc. - positional parameters
* `"$@"` - array-like construct of all of the positional parameters
* `$#` - number of positional arguments
* `"$*"` - IFS expansion of all positional parameters

### Process basics

In the simplest terms, a process is any running program with its address space. So how can we identify running processes? The Process Identifier (PID), which is just a unique number assigned to a process for the duration of its execution.

Processes are further identified by their user and group identifiers. Let's start with the *real* user and group identifiers, which give information about the user and group to which a process belongs. Any process will inherit these items from its parent process.

Another area to look at is that of effective user ID, effective group ID, and supplementary group ID. These three IDs are used to determine the permission that a process has to perform certain actions (such as accessing a file). One special effective user ID is `0`, which means that the process running under this effective ID will bypass all of the permission checks that the kernel has in place for all unprivileged processes.

Because processes get spawned from other processes, there must be some genesis to this mess. That comes in the form of the `init` process, from which all other processes derive in some form. This process can only be killed on system shutdown, and it will always have PID 1 associated with it. Note that in `systemd` systems, the `init` program is linked to the `systemd` binary.

At some point, you may want to view all of the running processes on your system. For this, the `ps` command is a nifty tool. The two most common methods of listing all processes with this command that you'll see are `ps -ef` and `ps aux`. While there are some very minor differences in the output format of these commands, you should be getting the same information from each of them. The presence of two different methods for listing processes in this way stems from the difference in BSD and non-BSD implementations of `ps`, but all modern `ps` binaries support both sets of options.

When a child process's parent terminates, it becomes an orphan. At this point, the `init` process adopts it and becomes its new parent. Alternatively, a zombie process is one that is waiting for its parent to fetch its termination status via a `wait()`-style system call. Although the kernel does release the resources originally allocated to the zombie process, information like its termination status and PID will persist in the process table until its parent cleans it up.

### Jobs

A job is a concept of Bash (and some other shells). You can think of a job as any program that you interactively start that does not detach (i.e., a daemon).

You can suspend the current job via `Ctrl-Z`, at which point it will suspend execution until sent to the bacgkround or . You can also force a job to run in the background from the get-go by appending a `&` to its invocation.

You can examine current jobs via the `jobs` command. You can resume execution of a suspended job in the background via `bg`. You can then bring one of these background jobs back to the foreground via the `fg` command. Here is a simple example:
```sh
$ sleep 20 &
[1] 3690
$ sleep 20
^Z
[2]+  Stopped                 sleep 20
$ jobs
[1]-  Running                 sleep 20 &
[2]+  Stopped                 sleep 20
$ bg %2
[2]+ sleep 20 &
$ jobs
[1]-  Running                 sleep 20 &
[2]+  Running                 sleep 20 &
$ fg %1
sleep 20
$ jobs
[2]+  Running                 sleep 20 &
$ jobs
[2]+  Done                    sleep 20
```

### Sockets

Sockets are an important part of the way networking operates on Linux. Sockets are a two-way communication pipe which act like FIFOs. Linux sockets are a special file in the file system. There are a few differnt types of sockets available in a Linux system.

The first type of sockets are referred to as Regular Sockets. Each layer of the protocol stack will process its respective component of the data, perform checksum validation, remove its respective header and trailer, and pass up the derived contents to the immediate upper layer.

Raw Sockets are the next up. These involve no layer checking and leave it up to the application to interpret the data. These are often used in packet capture / sniffer programs, but they require root privileges.

Processes can also use sockets to communicate with each other via Inter-Process Communication (IPC).

### Networked services

* `ntpd` - Network Time Protocol daemon
* `httpd` - Hyper Text Transfer Protocol daemon
* `sshd` - Secure SHell daemon
* `postfix` / `sendmail` - Mail Server daemon
* `snmpd` - Simple Network Management Protocol daemon
* `iptables` / `nftables` / `ufw` - Network Filtering Protocol Service
* `nfsd` - Network File System Server daemon
* `dnsmasq` / `nscd` - Name Server Cache daemon
* `named` (bind) - Dynamic Naming Service Server daemon
* `smbd` (samba) - Server Message Block Server daemon

### DNS

There are a few files that are used in the DNS resolution process:

* `/etc/hosts` - list of host-IP mappings
* `/etc/resolv.conf` - name server settings
* `/etc/nsswitch.conf` - determines DNS settings

The default order for resolution is: local cache, `/etc/hosts`, and then DNS. This order can be changed via `/etc/resolv.conf`.

### Network Super Servers

These servers listen for network connections on behalf of other programs. This helps reduce memory load and improve security. Some examples of super servers include `inetd` (older) and `xinetd` (newer).


## Auditing & Logging

The following are important logs typically found on Linux systems:

* `/var/log/messages` / `/var/log/syslog` - global messages across the system
* `/var/log/auth.log` - authentication logs (Debian-based systems)
* `/var/log/secure` - authentication logs (RHEL-based systems)
* `/var/log/kern.log` - kernel logs
* `/var/log/cron.log` - cron job logs
* `/var/log/maillog` - mail server logs
* `/var/log/httpd` - Apache access and error logs directory
* `/var/log/utmp` - gives a complete picture of user logins at which terminals, logouts, system events, current status of the system, and system boot time
* `/var/log/wtmp` - gives historical data of `utmp`
* `/var/log/btmp` - records only failed login attempts
* `/var/log/lastlog` - database file showing last login or each account

Another way to view kernel events is through the `dmesg` command, which prints the message buffer of the kernel.

A key logging utility on a lot of Linux systems is Syslog:

* Protocol standard defined by RFC 5424
* Main implementation is `rsyslog` (with configuration found at `/etc/rsyslog.conf`
* Standard ports are UDP / TCP 514
* Gets messages from `/dev/log` socket

`journald` is an essential logging utility for `systemd`:

* Works with PIDs, process names, and service IDs based on severity codes
* Configuration found at `/etc/systemd/journald.conf`
* Default configurations generally implement ForwardToSyslog
* The `journalctl` program enables granular querying of `/var/log/journal`

`auditd` is the user-space component to the Linux Auditing System:

* Linux Auditing System operates at the kernel level
* Rules and configuration are kept in `/etc/audit/autidd.rules` and `/etc/audit/autid.conf`, respectively
* `auditd` has been integrated into `systemd` on modern distributions
* `auditctl`, `aureport` (produces summary reports), and `ausearch` provide control and querying functionality

Best logging practices include:

* Remotely and locally stored
* Aggregated
* Analyzed by qualified ISSOs / analysts
* Regularly audited


## Linux Exploitation

This part of this guide is less important for the actual curriculum and more important for maintaining access to your classmates' machines during the lecture portions of the course. Some resources to get your feet wet:

* [MITRE's comprehensive reference](https://attack.mitre.org/matrices/enterprise/linux/)
* [Metasploit service persistence](https://www.rapid7.com/db/modules/exploit/linux/local/service_persistence)
* [Metasploit cron persistence](https://www.rapid7.com/db/modules/exploit/linux/local/cron_persistence)

Unlock this portion of the guide for 5 easy payments of $19.99 and you too can become `bigmikenelson`.