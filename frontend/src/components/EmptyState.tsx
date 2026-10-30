import React from 'react';

interface EmptyStateProps {
  icon: React.ReactNode | React.ElementType;
  title: string;
  description: string;
}

const EmptyState: React.FC<EmptyStateProps> = ({ icon: Icon, title, description }) => {
  const isComponent = typeof Icon === 'function' || (typeof Icon === 'object' && Icon !== null && '$$typeof' in Icon);

  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="text-slate-400 dark:text-slate-500 mb-4">
        {isComponent ? React.createElement(Icon as React.ComponentType<{ className?: string }>, { className: 'w-12 h-12 mx-auto' }) : (Icon as React.ReactNode)}
      </div>
      <h3 className="text-lg font-semibold text-gray-700 dark:text-slate-300 mb-2">
        {title}
      </h3>
      <p className="text-sm text-slate-500 dark:text-slate-400 max-w-md">
        {description}
      </p>
    </div>
  );
};

export default EmptyState;
