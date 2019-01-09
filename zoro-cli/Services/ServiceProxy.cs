﻿using System.ServiceProcess;

namespace Zoro.Services
{
    internal class ServiceProxy : ServiceBase
    {
        private ConsoleServiceBase service;

        public ServiceProxy(ConsoleServiceBase service)
        {
            this.service = service;
        }

        protected override void OnStart(string[] args)
        {
            service.OnStart(args);
        }

        protected override void OnStop()
        {
            service.OnStop();
        }
    }
}
