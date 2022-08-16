using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TaskScheduler;
using System.Security.Principal;
namespace SharpPowers
{
    internal class Scheduler
    {
        public static uint runningTaskPid = 0;
        public static bool createScheduledTask(string taskName, string taskProgram, string taskArguments, string userName, bool extendedPriv )
        {
            String[] privs = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege" };
            String[] extPrivs = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeImpersonatePrivilege", "SeIncreaseQuotaPrivilege", "SeShutdownPrivilege", "SeUndockPrivilege", "SeIncreaseWorkingSetPrivilege", "SeTimeZonePrivilege", "SeSystemtimePrivilege" };
            ITaskService taskService = new TaskScheduler.TaskScheduler();
            taskService.Connect();
            ITaskFolder folder = taskService.GetFolder(@"\");
            try
            {
                folder.DeleteTask(taskName, 0);
            }
            catch (System.IO.FileNotFoundException)
            {

            }
            ITaskDefinition taskDefinition = taskService.NewTask(0);
            taskDefinition.RegistrationInfo.Description = taskName;
            taskDefinition.Principal.UserId = userName;
            taskDefinition.Principal.LogonType = _TASK_LOGON_TYPE.TASK_LOGON_SERVICE_ACCOUNT;
            IPrincipal2 principal = (IPrincipal2) taskDefinition.Principal;
            if (extendedPriv)
            {
                for (int i = 0; i < extPrivs.Length; i++)
                {
                    principal.AddRequiredPrivilege(extPrivs[i]);
                }
            }
            else
            {
                for (int i = 0; i < privs.Length; i++)
                {
                    principal.AddRequiredPrivilege(privs[i]);
                }
            }
            IActionCollection actions = taskDefinition.Actions;
            IExecAction execAction = (IExecAction)actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            execAction.Path = taskProgram;
            execAction.Arguments = taskArguments;
            folder.RegisterTaskDefinition(taskName, taskDefinition, 6, null, null, _TASK_LOGON_TYPE.TASK_LOGON_NONE, null);
            return true;
        }
        public static bool startScheduledTask(string taskName)
        {
            ITaskService taskService = new TaskScheduler.TaskScheduler();
            taskService.Connect();
            ITaskFolder folder = taskService.GetFolder(@"\");
            IRegisteredTask task = folder.GetTask(taskName);
            if (task != null)
            {
                IRunningTask runningTask = task.Run(null);
                runningTaskPid = runningTask.EnginePID;
                return true;
            }
            return false;
        }
        public static bool DeleteScheduledTask(string taskName)
        {
            ITaskService taskService = new TaskScheduler.TaskScheduler();
            taskService.Connect();
            ITaskFolder folder = taskService.GetFolder(@"\");
            folder.DeleteTask(taskName, 0);
            return true;
        }
    }
}
