import React from 'react';

interface StatCardProps {
  icon: React.ReactNode | React.ElementType;
  label?: string;
  title?: string;
  value: string | number;
  color?: string;
  bgColor?: string;
}

const StatCard: React.FC<StatCardProps> = ({
  icon: Icon,
  label,
  title,
  value,
  color = 'text-white dark:text-white',
  bgColor = 'bg-slate-700 dark:bg-slate-700',
}) => {
  const displayLabel = title || label;
  const isComponent = typeof Icon === 'function' || (typeof Icon === 'object' && Icon !== null && '$$typeof' in Icon);

  return (
    <div className="rounded-lg p-6 flex items-center gap-4 bg-white dark:bg-slate-800 border border-gray-200 dark:border-slate-700 shadow-sm">
      <div className={`rounded-lg p-3 ${bgColor}`}>
        {isComponent ? React.createElement(Icon as React.ComponentType<{ className?: string }>, { className: 'w-6 h-6' }) : (Icon as React.ReactNode)}
      </div>
      <div>
        <p className="text-sm text-slate-500 dark:text-slate-400">{displayLabel}</p>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
      </div>
    </div>
  );
};

export default StatCard;
