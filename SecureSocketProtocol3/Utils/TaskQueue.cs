using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace SecureSocketProtocol3.Utils
{
    public class TaskQueue<T>
    {
        private Action<T> callback;
        private Queue<T> tasks;
        private bool ThreadRunning = false;
        public uint MaxItems = 100;

        public TaskQueue(Action<T> Callback, uint MaxItems = 100)
        {
            this.tasks = new Queue<T>();
            this.callback = Callback;
            this.MaxItems = MaxItems;
        }

        public void Enqueue(T value)
        {
            lock (tasks)
            {
                while (tasks.Count > MaxItems && !ThreadRunning)
                    ExecuteTasks();

                tasks.Enqueue(value);
                if (!ThreadRunning)
                {
                    ThreadRunning = true;
                    ThreadPool.QueueUserWorkItem((object obj) => WorkerThread());
                }
            }
        }

        private void WorkerThread()
        {
            ExecuteTasks();
            ThreadRunning = false;
        }

        public void ClearTasks()
        {
            lock (tasks)
            {
                tasks.Clear();
            }
        }

        private void ExecuteTasks()
        {
            lock (tasks)
            {
                while (tasks.Count > 0)
                {
                    try
                    {
                        T obj;
                        lock (tasks)
                        {
                            obj = tasks.Dequeue();
                        }
                        callback(obj);
                    }
                    catch (Exception ex)
                    {
                        SysLogger.Log(ex.Message, SysLogType.Error, ex);

                    }
                }
            }
        }
    }
}
