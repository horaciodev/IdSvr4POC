using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace IdSvr4POC.Models
{
    public class ApplicationRole: IdentityRole
    {
        [MaxLength(256)]
        public string RoleDescription { get; set;}
    }
}