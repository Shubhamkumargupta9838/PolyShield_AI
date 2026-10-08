import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import '@testing-library/jest-dom';
import App from './App';

describe('App Component — Frontend Integration & UI State Tests', () => {
  it('renders PolyShield brand header and navigation items', () => {
    render(<App />);

    expect(screen.getByText('PolyShield')).toBeInTheDocument();
    expect(screen.getByText('AI')).toBeInTheDocument();

    expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Upload Sample').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Scan History').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Analysis Report').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Settings & Security').length).toBeGreaterThan(0);
  });

  it('switches navigation tabs when buttons are clicked', () => {
    render(<App />);

    // Click Upload Sample tab
    const uploadBtn = screen.getAllByText('Upload Sample')[0];
    fireEvent.click(uploadBtn);
    expect(screen.getByText('PE Executable File Scanner')).toBeInTheDocument();

    // Click Scan History tab
    const historyBtn = screen.getAllByText('Scan History')[0];
    fireEvent.click(historyBtn);
    expect(screen.getByText(/Scan records and state machine tracking active/i)).toBeInTheDocument();

    // Click Settings tab
    const settingsBtn = screen.getAllByText('Settings & Security')[0];
    fireEvent.click(settingsBtn);
    expect(screen.getByText('Platform Settings & Security Policies')).toBeInTheDocument();
  });

  it('displays hardened security controls and disclosures in Settings view', () => {
    render(<App />);

    const settingsBtn = screen.getAllByText('Settings & Security')[0];
    fireEvent.click(settingsBtn);

    expect(screen.getByText(/Path Traversal Shield: Active/i)).toBeInTheDocument();
    expect(screen.getByText(/Authentication: Bearer JWT/i)).toBeInTheDocument();
  });
});
