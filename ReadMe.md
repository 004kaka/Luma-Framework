Luma is modding framework that facilitates improving graphics in DirectX 11 games.
It leverages the ReShade Addon system to add or modify rendering passes (and replace shaders (e.g. post processing)) through DirectX hooks.
While most of the generic shaders code is focused on HDR output support, there's a lot more to it already (like DLSS support), and no limit to what it can do.
Multiple games are already in the code, including a template project, and adding a new one is relatively easy.
Luma also acts as a graphics analyzer, having deep debugging capabilities (capturing all draw/dispatch commands and state changes in DX (e.g. SRVs/RTVs/UAVs/DSV/CBs etc etc)), download the graphics analyzer to just use that in any DX11 game.
<img width="854" height="848" alt="Mafia3DefinitiveEdition_awDHUAZNqF" src="https://github.com/user-attachments/assets/d8a27757-9f97-47c7-a896-08a99f62f597" />


...
