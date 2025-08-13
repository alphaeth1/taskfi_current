'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Users, Calendar, DollarSign } from 'lucide-react';
import ChatInterface from '../../../../components/ChatInterface';

interface JobDetails {
  id: string;
  title: string;
  description: string;
  budget: number;
  deadline?: string;
  status: string;
  hirer: {
    id: string;
    name: string;
    username: string;
    avatarUrl?: string;
  };
  freelancer?: {
    id: string;
    name: string;
    username: string;
    avatarUrl?: string;
  };
}

export default function JobChatPage({ params }: { params: { id: string } }) {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [job, setJob] = useState<JobDetails | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (status === 'loading') return;
    if (!session) {
      router.push('/auth/signin');
      return;
    }
    loadJobDetails();
  }, [session, status, params.id]);

  const loadJobDetails = async () => {
    try {
      const response = await fetch(`/api/jobs/${params.id}/messages`);
      if (!response.ok) {
        if (response.status === 403) {
          setError('You do not have access to this job chat.');
        } else if (response.status === 404) {
          setError('Job not found.');
        } else {
          setError('Failed to load job details.');
        }
        return;
      }
      
      const data = await response.json();
      setJob(data.job);
    } catch (error) {
      console.error('Error loading job details:', error);
      setError('Failed to load job details.');
    } finally {
      setIsLoading(false);
    }
  };

  if (status === 'loading' || isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full mx-4">
          <div className="text-center">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Users className="w-8 h-8 text-red-600" />
            </div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Access Denied</h2>
            <p className="text-gray-600 mb-6">{error}</p>
            <button
              onClick={() => router.back()}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Job not found</h2>
          <button
            onClick={() => router.back()}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Go Back
          </button>
        </div>
      </div>
    );
  }

  const isHirer = job.hirer.id === session?.user?.id;
  const otherParticipant = isHirer ? job.freelancer : job.hirer;

  if (!otherParticipant) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white p-8 rounded-lg shadow-md max-w-md w-full mx-4">
          <div className="text-center">
            <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Users className="w-8 h-8 text-yellow-600" />
            </div>
            <h2 className="text-xl font-semibold text-gray-900 mb-2">No Chat Available</h2>
            <p className="text-gray-600 mb-6">
              {isHirer 
                ? "No freelancer has been assigned to this job yet."
                : "You are not the assigned freelancer for this job."
              }
            </p>
            <button
              onClick={() => router.back()}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto px-4 py-6">
        {/* Header */}
        <div className="mb-6">
          <button
            onClick={() => router.back()}
            className="flex items-center text-gray-600 hover:text-gray-900 mb-4 transition-colors"
          >
            <ArrowLeft className="w-5 h-5 mr-2" />
            Back to Job
          </button>
          
          <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between">
              <div className="flex-1">
                <h1 className="text-2xl font-bold text-gray-900 mb-2">{job.title}</h1>
                <p className="text-gray-600 mb-4 line-clamp-2">{job.description}</p>
                
                <div className="flex flex-wrap items-center gap-6 text-sm text-gray-500">
                  <div className="flex items-center">
                    <DollarSign className="w-4 h-4 mr-1" />
                    <span className="font-medium">${job.budget.toLocaleString()}</span>
                  </div>
                  {job.deadline && (
                    <div className="flex items-center">
                      <Calendar className="w-4 h-4 mr-1" />
                      <span>Due {new Date(job.deadline).toLocaleDateString()}</span>
                    </div>
                  )}
                  <div className="flex items-center">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${{
                      'OPEN': 'bg-green-100 text-green-800',
                      'IN_PROGRESS': 'bg-blue-100 text-blue-800',
                      'COMPLETED': 'bg-gray-100 text-gray-800',
                      'CANCELLED': 'bg-red-100 text-red-800',
                    }[job.status] || 'bg-gray-100 text-gray-800'}`}>
                      {job.status.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 lg:mt-0 lg:ml-6">
                <div className="flex items-center space-x-4">
                  <div className="text-center">
                    <p className="text-sm text-gray-500 mb-2">{isHirer ? 'Freelancer' : 'Client'}</p>
                    <div className="flex items-center space-x-2">
                      {otherParticipant.avatarUrl ? (
                        <img
                          src={otherParticipant.avatarUrl}
                          alt={otherParticipant.name}
                          className="w-10 h-10 rounded-full object-cover"
                        />
                      ) : (
                        <div className="w-10 h-10 rounded-full bg-gradient-to-r from-purple-500 to-blue-500 flex items-center justify-center text-white font-medium">
                          {otherParticipant.name.charAt(0).toUpperCase()}
                        </div>
                      )}
                      <div>
                        <p className="font-medium text-gray-900">{otherParticipant.name}</p>
                        <p className="text-sm text-gray-500">@{otherParticipant.username}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Chat Interface */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 h-[600px]">
          <ChatInterface
            jobId={job.id}
            jobTitle={job.title}
            otherParticipant={otherParticipant}
          />
        </div>
      </div>
    </div>
  );
}