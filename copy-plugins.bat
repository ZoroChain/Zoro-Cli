xcopy ..\Zoro-Plugins\AppChainPlugin\bin\Debug\netstandard2.0\AppChainPlugin.dll zoro-cli\bin\Debug\netcoreapp2.0\Plugins\ /y /q
xcopy ..\Zoro-Plugins\AppChainPlugin\AppChainPlugin zoro-cli\bin\Debug\netcoreapp2.0\Plugins\AppChainPlugin\ /y /q

xcopy ..\Zoro-Plugins\RpcAgent\bin\Debug\netstandard2.0\RpcAgent.dll zoro-cli\bin\Debug\netcoreapp2.0\Plugins\ /y /q
xcopy ..\Zoro-Plugins\RpcAgent\RpcAgent zoro-cli\bin\Debug\netcoreapp2.0\Plugins\RpcAgent\ /y /q

xcopy ..\Zoro-Plugins\SimplePolicy\bin\Debug\netstandard2.0\SimplePolicy.dll zoro-cli\bin\Debug\netcoreapp2.0\Plugins\ /y /q
xcopy ..\Zoro-Plugins\SimplePolicy\SimplePolicy zoro-cli\bin\Debug\netcoreapp2.0\Plugins\SimplePolicy\ /y /q

xcopy ..\Zoro-Plugins\ApplicationLogs\bin\Debug\netstandard2.0\ApplicationLogs.dll zoro-cli\bin\Debug\netcoreapp2.0\Plugins\ /y /q
xcopy ..\Zoro-Plugins\ApplicationLogs\ApplicationLogs zoro-cli\bin\Debug\netcoreapp2.0\Plugins\ApplicationLogs\ /y /q

pause