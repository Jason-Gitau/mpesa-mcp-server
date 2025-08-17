import logging
import asyncio
from typing import Dict, Any, List
from mcp.server import Server
from mcp.types import Tool, TextContent

# Import your existing services (SAME business logic!)
from services.mpesa_service import MPesaService
from services.audit_service import AuditService
from models.transaction import TransactionModel
from models.organization import OrganizationModel

logger = logging.getLogger(__name__)

class MPesaMCPServer:
    """MCP Server for M-Pesa integration - shares logic with REST API"""
    
    def __init__(self):
        self.server = Server("mpesa-mcp")
        self.mpesa_service = MPesaService()
        
        # Register MCP handlers
        self.server.list_tools()(self.list_tools)
        self.server.call_tool()(self.call_tool)
        
    async def list_tools(self) -> List[Tool]:
        """Expose your M-Pesa functions as MCP tools"""
        return [
            Tool(
                name="mpesa_stk_push",
                description="Initiate M-Pesa STK Push payment to collect money from customer",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "phone_number": {
                            "type": "string", 
                            "description": "Customer phone number (format: 254712345678)"
                        },
                        "amount": {
                            "type": "number", 
                            "description": "Amount to charge (minimum 1 KES)"
                        },
                        "account_reference": {
                            "type": "string", 
                            "description": "Account reference for the payment"
                        },
                        "transaction_desc": {
                            "type": "string", 
                            "description": "Description of the transaction"
                        },
                        "org_id": {
                            "type": "string", 
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string", 
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["phone_number", "amount", "account_reference", "transaction_desc", "org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_check_status",
                description="Check the status of an M-Pesa STK Push transaction",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "checkout_request_id": {
                            "type": "string",
                            "description": "CheckoutRequestID from STK Push response"
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["checkout_request_id", "org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_check_balance",
                description="Check M-Pesa account balance for the organization",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "account_type": {
                            "type": "string",
                            "description": "Account type to check (PAYBILL, TILL)",
                            "enum": ["PAYBILL", "TILL"],
                            "default": "PAYBILL"
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_bulk_payment",
                description="Process bulk B2C payments to multiple recipients",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "payments": {
                            "type": "array",
                            "description": "List of payments to process",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "phone_number": {"type": "string"},
                                    "amount": {"type": "number"},
                                    "account_reference": {"type": "string"},
                                    "remarks": {"type": "string"}
                                },
                                "required": ["phone_number", "amount"]
                            }
                        },
                        "batch_name": {
                            "type": "string",
                            "description": "Name for this batch of payments"
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["payments", "batch_name", "org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_reverse_transaction",
                description="Reverse/refund an M-Pesa transaction",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "transaction_id": {
                            "type": "string",
                            "description": "M-Pesa transaction ID to reverse"
                        },
                        "amount": {
                            "type": "number",
                            "description": "Amount to reverse"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for the reversal"
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["transaction_id", "amount", "reason", "org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_transaction_history",
                description="Get transaction history with filtering options",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_date": {
                            "type": "string",
                            "description": "Start date for filtering (YYYY-MM-DD)"
                        },
                        "end_date": {
                            "type": "string",
                            "description": "End date for filtering (YYYY-MM-DD)"
                        },
                        "status": {
                            "type": "string",
                            "description": "Filter by transaction status"
                        },
                        "transaction_type": {
                            "type": "string",
                            "description": "Filter by transaction type"
                        },
                        "phone_number": {
                            "type": "string",
                            "description": "Filter by phone number"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of records to return",
                            "default": 100
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["org_id", "user_id"]
                }
            ),
            
            Tool(
                name="mpesa_generate_report",
                description="Generate financial reports for the organization",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "report_type": {
                            "type": "string",
                            "description": "Type of report to generate",
                            "enum": ["DAILY", "WEEKLY", "MONTHLY", "CUSTOM"],
                            "default": "DAILY"
                        },
                        "date_from": {
                            "type": "string",
                            "description": "Start date for report (YYYY-MM-DD)"
                        },
                        "date_to": {
                            "type": "string",
                            "description": "End date for report (YYYY-MM-DD)"
                        },
                        "org_id": {
                            "type": "string",
                            "description": "Organization ID for multi-tenant isolation"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID making the request"
                        }
                    },
                    "required": ["date_from", "date_to", "org_id", "user_id"]
                }
            )
        ]
    
    async def call_tool(self, name: str, arguments: dict) -> List[TextContent]:
        """Execute MCP tools - uses SAME business logic as REST API!"""
        try:
            result = None
            
            if name == "mpesa_stk_push":
                # SAME function as REST endpoint!
                result = await self.mpesa_service.stk_push_payment(
                    phone_number=arguments['phone_number'],
                    amount=float(arguments['amount']),
                    account_reference=arguments['account_reference'],
                    transaction_desc=arguments['transaction_desc'],
                    user_id=arguments['user_id'],
                    org_id=arguments['org_id']
                )
                
                # Same audit logging as REST
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'STK_PUSH_INITIATED', 'stk_push_payment',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_check_status":
                # SAME function as REST endpoint!
                result = await self.mpesa_service.check_transaction_status(
                    checkout_request_id=arguments['checkout_request_id'],
                    user_id=arguments['user_id'],
                    org_id=arguments['org_id']
                )
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'TRANSACTION_STATUS_CHECK', 'check_transaction_status',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_check_balance":
                # SAME function as REST endpoint!
                account_type = arguments.get('account_type', 'PAYBILL')
                result = await self.mpesa_service.get_account_balance(
                    user_id=arguments['user_id'],
                    org_id=arguments['org_id'],
                    account_type=account_type
                )
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'BALANCE_CHECK', 'get_account_balance',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_bulk_payment":
                # SAME function as REST endpoint!
                result = await self.mpesa_service.bulk_payment(
                    payments=arguments['payments'],
                    batch_name=arguments['batch_name'],
                    user_id=arguments['user_id'],
                    org_id=arguments['org_id']
                )
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'BULK_PAYMENT', 'bulk_payment',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_reverse_transaction":
                # SAME function as REST endpoint!
                result = await self.mpesa_service.reverse_transaction(
                    transaction_id=arguments['transaction_id'],
                    amount=float(arguments['amount']),
                    reason=arguments['reason'],
                    user_id=arguments['user_id'],
                    org_id=arguments['org_id']
                )
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'TRANSACTION_REVERSAL', 'reverse_transaction',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_transaction_history":
                # SAME function as REST endpoint!
                filters = {k: v for k, v in arguments.items() 
                          if k not in ['org_id', 'user_id'] and v is not None}
                
                result = await TransactionModel.get_transaction_history(
                    org_id=arguments['org_id'],
                    filters=filters
                )
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'TRANSACTION_HISTORY_QUERY', 'get_transaction_history',
                    arguments, {'count': len(result)}, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
                
            elif name == "mpesa_generate_report":
                # SAME function as REST endpoint!
                from datetime import datetime
                
                report_data = await TransactionModel.generate_report_data(
                    arguments['org_id'], arguments['date_from'], arguments['date_to']
                )
                
                report_data.update({
                    'organization_id': arguments['org_id'],
                    'generated_at': datetime.now().isoformat(),
                    'period': f"{arguments['date_from']} to {arguments['date_to']}",
                    'report_type': arguments.get('report_type', 'DAILY')
                })
                
                report_id = await TransactionModel.store_report(
                    arguments['org_id'], arguments.get('report_type', 'DAILY'), 
                    f"{arguments.get('report_type', 'DAILY')} Report", 
                    arguments['date_from'], arguments['date_to'], 
                    report_data, arguments['user_id']
                )
                
                result = {**report_data, 'report_id': str(report_id)}
                
                await AuditService.log_audit(
                    arguments['user_id'], arguments['org_id'], 
                    'REPORT_GENERATED', 'generate_report',
                    arguments, result, 'SUCCESS', 'MCP_CLIENT', 'MCP_TOOL'
                )
            
            else:
                raise ValueError(f"Unknown tool: {name}")
            
            return [TextContent(
                type="text",
                text=f"Success: {result}"
            )]
            
        except Exception as e:
            logger.error(f"MCP tool {name} failed: {e}")
            
            # Same error audit logging as REST
            await AuditService.log_audit(
                arguments.get('user_id'), arguments.get('org_id'), 
                f'{name.upper()}_FAILED', name,
                arguments, {'error': str(e)}, 'FAILED', 'MCP_CLIENT', 'MCP_TOOL'
            )
            
            return [TextContent(
                type="text", 
                text=f"Error: {str(e)}"
            )]

    async def run(self, transport):
        """Run the MCP server"""
        await self.server.run(transport)

# Global instance
mcp_server = MPesaMCPServer()
