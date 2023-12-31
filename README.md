# License Notice
Any usage of this project is subjected to the terms of the license of this project, (see [License](#License)).

# NoConnect

#### Definitely for user that willing to break their online experiences. Therefore, issues that occur when using this should be reported here.

Prevent connections to remote<b>*</b> (mostly) but not limited to, such as update, joining server, etc.

*Except localhost resources and default allowed hosts.

Credit to contributors of https://github.com/InfinityStudio/NonUpdate for references.

Note
----
By default, the following hosts listed below are allowed.
```
*.minecraft.net
*.minecraftservices.com
*.mojang.com
```
You can change this in `./config/noconnect.toml`

Tested with Minecraft Forge 1.14.x - 1.19.x.

<a name="License" />License
--------
Licensed under the Open Software License version 3.0, see [LICENSE](LICENSE.txt) for more details.

Attributions
--------
This project contain code segment that referenced from 
[OkHttp](https://github.com/square/okhttp/blob/cd722373281202492043f4294fccfe6f691ddc01/okhttp/src/main/kotlin/okhttp3/CertificatePinner.kt#L276),
licensed under Apache 2.0.
