using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
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
