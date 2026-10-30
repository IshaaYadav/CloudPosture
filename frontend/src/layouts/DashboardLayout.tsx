import React, { useState, useEffect } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import {
  Shield,
  LayoutDashboard,
  Server,
  Database,
  ShieldAlert,
  History,
  Menu,
  X,
  Sun,
  Moon,
} from 'lucide-react';
import api from '../services/api';
import type { AWSStatus } from '../types';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/instances', label: 'EC2 Instances', icon: Server },
  { to: '/buckets', label: 'S3 Buckets', icon: Database },
  { to: '/findings', label: 'Security Findings', icon: ShieldAlert },
  { to: '/history', label: 'Scan History', icon: History },
];

interface DashboardLayoutProps {
  children?: React.ReactNode;
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(true);
  const [awsStatus, setAwsStatus] = useState<AWSStatus | null>(null);

  useEffect(() => {
    document.documentElement.classList.add('dark');
  }, []);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const status = await api.getAWSStatus();
        setAwsStatus(status);
      } catch {
        setAwsStatus(null);
      }
    };
    fetchStatus();
  }, []);

  const toggleDarkMode = () => {
    setDarkMode((prev) => !prev);
  };

  const isConnected = awsStatus?.connected ?? false;

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-slate-900 text-gray-900 dark:text-white">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-40 w-64 transform transition-transform duration-200 ease-in-out
          bg-white dark:bg-slate-800 border-r border-gray-200 dark:border-slate-700
          lg:relative lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-200 dark:border-slate-700">
          <Shield className="w-8 h-8 text-blue-500" />
          <div>
            <h1 className="text-base font-bold leading-tight text-gray-900 dark:text-white">
              Cloud Posture
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">Scanner</p>
          </div>
          <button
            className="ml-auto lg:hidden text-slate-400 hover:text-white"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex flex-col gap-1 px-3 py-4">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-600 dark:text-blue-400 border-l-2 border-blue-600 dark:border-blue-400'
                    : 'text-slate-600 dark:text-slate-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-slate-700/50'
                }`
              }
            >
              <Icon className="w-5 h-5" />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>

      {/* Main area */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top Header */}
        <header className="h-16 flex items-center justify-between px-4 sm:px-6 bg-white dark:bg-slate-800 border-b border-gray-200 dark:border-slate-700 flex-shrink-0">
          {/* Left: hamburger */}
          <button
            className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-slate-700"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1" />

          {/* Right side controls */}
          <div className="flex items-center gap-4">
            {/* AWS status */}
            <div className="flex items-center gap-2 text-sm">
              <span className="relative flex h-2.5 w-2.5">
                {isConnected && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
                )}
                <span
                  className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                    isConnected ? 'bg-green-500' : 'bg-red-500'
                  }`}
                />
              </span>
              <span className="hidden sm:inline text-slate-600 dark:text-slate-400">
                {isConnected ? 'AWS Connected' : 'AWS Disconnected'}
              </span>
            </div>

            {/* Dark mode toggle */}
            <button
              onClick={toggleDarkMode}
              className="p-2 rounded-lg text-slate-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-slate-700 transition-colors"
              title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
          </div>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children || <Outlet />}
        </main>
      </div>

      <Toaster
        position="top-right"
        toastOptions={{
          className: 'dark:bg-slate-700 dark:text-white',
          duration: 4000,
        }}
      />
    </div>
  );
};

export default DashboardLayout;
