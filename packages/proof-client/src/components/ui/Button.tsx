import React from "react";
import clsx from "clsx";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary";
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({ 
  variant = "primary", 
  className, 
  children, 
  ...props 
}) => {
  const baseStyles = "px-4 py-2 rounded font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";
  const variantStyles = {
    primary: "bg-blue-600 hover:bg-blue-700 text-white",
    secondary: "bg-gray-700 hover:bg-gray-600 text-white border border-gray-600",
  };

  return (
    <button
      className={clsx(baseStyles, variantStyles[variant], className)}
      {...props}
    >
      {children}
    </button>
  );
};
