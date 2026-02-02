using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Application_Security_Practical_Assignment.Migrations
{
    /// <inheritdoc />
    public partial class AddLastPasswordChangedUtc : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "LastPasswordChangedUtc",
                table: "MemberProfiles",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastPasswordChangedUtc",
                table: "MemberProfiles");
        }
    }
}
