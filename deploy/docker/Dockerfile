# Windows containers are heavy; we still ship a Dev container recipe (ServerCore).
# This is optional and not used in CI.
# escape=`
FROM mcr.microsoft.com/windows/servercore:ltsc2022
SHELL ["pwsh","-Command"]
RUN iwr https://win.rustup.rs -OutFile rustup-init.exe; Start-Process -FilePath .\rustup-init.exe -ArgumentList "-y" -Wait; Remove-Item .\rustup-init.exe
WORKDIR C:\src
COPY . .
RUN cargo build --release
ENTRYPOINT ["C:\src\target\release\yom.exe","run","--rules","examples\rules\mz.yar","--pids","self","--duration","5","--listen","0.0.0.0:9207"]
