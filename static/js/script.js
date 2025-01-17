import React from 'react';
import { Check, X } from 'lucide-react';

const PasswordRequirements = ({ password = '' }) => {
  const requirements = [
    {
      id: 'length',
      text: "At least 8 characters long",
      test: () => password.length >= 8
    },
    {
      id: 'uppercase',
      text: "At least one uppercase letter",
      test: () => /[A-Z]/.test(password)
    },
    {
      id: 'lowercase',
      text: "At least one lowercase letter",
      test: () => /[a-z]/.test(password)
    },
    {
      id: 'number',
      text: "At least one number",
      test: () => /\d/.test(password)
    },
    {
      id: 'special',
      text: "At least one special character (@$!%*#?&)",
      test: () => /[@$!%*#?&]/.test(password)
    }
  ];

  return (
    <div className="mt-4 p-4 rounded-lg border border-gray-200">
      <h3 className="text-sm font-medium mb-2" >Password Requirements:</h3>
      <div className="space-y-2">
        {requirements.map((req) => {
          const isMet = req.test();
          return (
            <div key={req.id} className="flex items-center gap-2">
              {isMet ? (
                <Check className="w-4 h-4 text-green-500 shrink-0" />
              ) : (
                <X className="w-4 h-4 text-red-500 shrink-0" />
              )}
              <span className={`text-sm ${isMet ? 'text-green-600' : 'text-gray-600'}`}>
                {req.text}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default PasswordRequirements;