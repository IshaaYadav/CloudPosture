import React from 'react';

interface StatusBadgeProps {
  status: 'PASS' | 'FAIL' | 'ERROR';
  size?: 'sm' | 'md';
}

const sizeStyles: Record<NonNullable<StatusBadgeProps['size']>, string> = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-3 py-1 text-sm',
};

const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'sm' }) => {
  let colorClasses = '';

  switch (status) {
    case 'PASS':
      colorClasses =
        'bg-green-100 text-green-700 border-green-300 dark:bg-green-500/20 dark:text-green-400 dark:border-green-500/30';
      break;
    case 'FAIL':
      colorClasses =
        'bg-red-100 text-red-700 border-red-300 dark:bg-red-500/20 dark:text-red-400 dark:border-red-500/30';
      break;
    case 'ERROR':
      colorClasses =
        'bg-amber-100 text-amber-700 border-amber-300 dark:bg-amber-500/20 dark:text-amber-400 dark:border-amber-500/30';
      break;
  }

  return (
    <span
      className={`inline-flex items-center font-semibold rounded-full border ${sizeStyles[size]} ${colorClasses}`}
    >
      {status}
    </span>
  );
};

export default StatusBadge;
